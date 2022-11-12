using System.Buffers;
using System.IO.Pipelines;
using System.IO.Ports;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace ZWave.Serial;

internal record struct DataFrameTransmission(DataFrame Frame, TaskCompletionSource TransmissionComplete);

/// <summary>
/// Coordinates communication with the Z-Wave Serial port
/// </summary>
internal sealed class ZWaveSerialPortCoordinator : IAsyncDisposable
{
    // INS12350 6.3 specifies that the host should use 3 retransmissions, meaning 4 total attempts
    private const int MaxTransmissionAttempts = 4;

    // INS12350 6.2.2
    private static readonly TimeSpan FrameDeliveryTimeout = TimeSpan.FromMilliseconds(1600);

    // INS12350 6.4.1 defines a Z-Wave module as unresponsive after 4 seconds, so retry 4 times with a 1 second delay between each.
    private const int MaxConnectionAttempts = 4;
    private const int ConnectionDelay = 1000;

    // Lock to manage a the current unsolicited or request/response frame flow. If one flow is in progress, a new one may not start.
    private readonly SemaphoreSlim _commLock = new (1, 1);

    private readonly ILogger _logger;

    private readonly SerialPort _serialPort;

    private readonly ChannelReader<DataFrameTransmission> _dataFrameSendChannelReader;

    private readonly ChannelWriter<DataFrame> _dataFrameReceiveChannelWriter;

    private readonly CancellationTokenSource _cancellationTokenSource;

    private readonly Task _readTask;

    private readonly Task _writeTask;

    private TaskCompletionSource<bool>? _frameDeliveryResultTaskSource;

    public ZWaveSerialPortCoordinator(
        ILogger logger,
        string portName,
        ChannelReader<DataFrameTransmission> dataFrameSendChannelReader,
        ChannelWriter<DataFrame> dataFrameReceiveChannelWriter)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _serialPort = CreateSerialPort(portName);
        _dataFrameSendChannelReader = dataFrameSendChannelReader ?? throw new ArgumentNullException(nameof(dataFrameSendChannelReader));
        _dataFrameReceiveChannelWriter = dataFrameReceiveChannelWriter ?? throw new ArgumentNullException(nameof(dataFrameReceiveChannelWriter));

        _serialPort.Open();
        _logger.LogSerialApiPortOpened(_serialPort.PortName);

        _cancellationTokenSource = new CancellationTokenSource();

        // Note: Since we're starting our own tasks, we don't need to ConfigureAwait anywhere downstream.
        _readTask = Task.Run(ReadAsync);
        _writeTask = Task.Run(WriteAsync);

        // Send a NAK as part of the initialization sequence (INS12350 6.1)
        SendFrame(Frame.NAK);
    }

    private static SerialPort CreateSerialPort(string portName)
    {
        if (string.IsNullOrEmpty(portName))
        {
            throw new ArgumentNullException(nameof(portName));
        }

        // INS12350 4.2.1 defines the serial port settings
        var serialPort = new SerialPort(
            portName,
            baudRate: 115200,
            parity: Parity.None,
            dataBits: 8,
            stopBits: StopBits.One);

        // Avoid throwing TimeoutExceptions.
        serialPort.ReadTimeout = SerialPort.InfiniteTimeout;
        serialPort.WriteTimeout = SerialPort.InfiniteTimeout;

        return serialPort;
    }

    public async ValueTask DisposeAsync()
    {
        _dataFrameReceiveChannelWriter.Complete();
        _cancellationTokenSource.Cancel();

        await _readTask;
        await _writeTask;

        _serialPort.Close();
        _logger.LogSerialApiPortClosed(_serialPort.PortName);
    }

    private async Task ReadAsync()
    {
        CancellationToken cancellationToken = _cancellationTokenSource.Token;

        PipeReader CreatePipeReader() => PipeReader.Create(_serialPort.BaseStream, new StreamPipeReaderOptions(leaveOpen: true));

        PipeReader serialPortReader = CreatePipeReader();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // This won't return until there is available data, so the actual read is outside the lock.
                // There is a race condition where we write a frame before we're notified of this read, however
                // the Z-Wave protocol will handle this conflict (by the chip sending us a CAN).
                ReadResult readResult = await serialPortReader.ReadAsync(cancellationToken);

                // While processing frames, lock to ensure no frames are written.
                await _commLock.WaitAsync();
                try
                {
                    ReadOnlySequence<byte> buffer = readResult.Buffer;

                    if (readResult.IsCanceled)
                    {
                        break;
                    }

                    while (FrameParser.TryParseData(_logger, ref buffer, out Frame frame))
                    {
                        switch (frame.Type)
                        {
                            case FrameType.ACK:
                            case FrameType.NAK:
                            case FrameType.CAN:
                            {
                                _logger.LogSerialApiFrameReceived(frame);

                                if (_frameDeliveryResultTaskSource != null)
                                {
                                    _frameDeliveryResultTaskSource.SetResult(frame.Type == FrameType.ACK);
                                }
                                else
                                {
                                    // We received a frame delivery notification unexpectedly. Just ignore.
                                    _logger.LogSerialApiUnexpectedFrame(frame);
                                }

                                break;
                            }
                            case FrameType.Data:
                            {
                                DataFrame dataFrame = frame.ToDataFrame();

                                if (dataFrame.IsChecksumValid())
                                {
                                    _logger.LogSerialApiDataFrameReceived(dataFrame);

                                    // Acknowledge any valid request immediately.
                                    SendFrame(Frame.ACK);

                                    await _dataFrameReceiveChannelWriter.WriteAsync(dataFrame, cancellationToken);
                                }
                                else
                                {
                                    _logger.LogSerialApiInvalidDataFrameReceived(dataFrame);

                                    // INS12350 5.4.6:
                                    //   Data frame MUST be considered invalid if it is received with an invalid checksum.
                                    //   A host or Z-Wave chip MUST return a NAK frame in response to an invalid Data frame.
                                    SendFrame(Frame.NAK);

                                    // INS12350 6.4.2:
                                    //   If a host application detects an invalid checksum three times in a row when receiving data frames, the 
                                    //   host application SHOULD invoke a hard reset of the device. If a hard reset line is not available, a soft 
                                    //   reset indication SHOULD be issued for the device.
                                    // TODO
                                }

                                break;
                            }
                            default:
                            {
                                // Ignore anything we don't recognize.
                                _logger.LogSerialApiFrameUnknownType(frame.Type);
                                break;
                            }
                        }
                    }

                    // Tell the PipeReader how much of the buffer has been consumed.
                    serialPortReader.AdvanceTo(buffer.Start, buffer.End);
                }
                finally
                {
                    _commLock.Release();
                }

                // Stop reading if there's no more data coming.
                if (readResult.IsCompleted)
                {
                    break;
                }
            }
            catch (OperationCanceledException)
            {
                // Swallow. If a specific read is cancelled, just keep retrying.
                _logger.LogSerialApiReadCancellation();
            }
            catch (Exception ex)
            {
                _logger.LogSerialApiReadException(ex);

                await _commLock.WaitAsync();
                try
                {
                    EnsurePortOpened();
                }
                finally
                {
                    _commLock.Release();
                }

                // When re-opening the port the stream gets recreated too, so we need to re-create the reader
                serialPortReader.CancelPendingRead();
                serialPortReader = CreatePipeReader();
            }
        }
    }

    private async Task WriteAsync()
    {
        CancellationToken cancellationToken = _cancellationTokenSource.Token;
        await foreach (DataFrameTransmission transmission in _dataFrameSendChannelReader.ReadAllAsync(cancellationToken))
        {
            bool transmissionSuccess = false;
            for (int transmissionAttempt = 0; transmissionAttempt < MaxTransmissionAttempts; transmissionAttempt++)
            {
                // INS12350 6.3 specifies a wait time for retransmissions
                if (transmissionAttempt > 0)
                {
                    int waitTimeMillis = 100 + ((transmissionAttempt - 1) * 1000);
                    await Task.Delay(waitTimeMillis, cancellationToken);
                }

                _frameDeliveryResultTaskSource = new TaskCompletionSource<bool>();

                // While writing frames, lock to ensure no frames are read and processed.
                await _commLock.WaitAsync();
                try
                {
                    // Send the command
                    await _serialPort.BaseStream.WriteAsync(transmission.Frame.Data, cancellationToken);
                    _logger.LogSerialApiDataFrameSent(transmission.Frame);
                }
                catch (Exception ex)
                {
                    _logger.LogSerialApiWriteException(ex);
                    EnsurePortOpened();
                    continue;
                }
                finally
                {
                    _commLock.Release();
                }

                // Wait for delivery confirmation. This cannot be in the lock as the reading thread is separate from this one, and
                // we cannot just directly read from the stream here as the other thread may get the read first, as it's also not inside
                // the lock so we cannot ensure it does not consume those bytes.
                bool frameDeliveryResult;
                try
                {
                    frameDeliveryResult = await _frameDeliveryResultTaskSource.Task.WaitAsync(FrameDeliveryTimeout, cancellationToken);
                }
                catch (TimeoutException)
                {
                    // INS12350 6.2.2 specifies that timeouts are treated as a NAK, which is not a success.
                    _logger.LogSerialApiFrameDeliveryAckTimeout();
                    frameDeliveryResult = false;
                }
                finally
                {
                    _frameDeliveryResultTaskSource = null;
                }

                if (frameDeliveryResult)
                {
                    // A data frame went through successfully.
                    transmissionSuccess = true;
                    break;
                }

                // In the case of a NAK or CAN, retransmit our data frame.
                _logger.LogSerialApiFrameTransmissionRetry(transmissionAttempt + 1);
            }

            if (transmissionSuccess)
            {
                transmission.TransmissionComplete.SetResult();
            }
            else
            {
                // INS12350 6.3: Flush/reopen the serial port after the three retransmissions.
                await _commLock.WaitAsync();
                try
                {
                    _serialPort.DiscardInBuffer();
                    _serialPort.DiscardOutBuffer();
                    _serialPort.Close();
                    EnsurePortOpened();
                }
                finally
                {
                    _commLock.Release();
                }

                transmission.TransmissionComplete.SetException(new ZWaveException(ZWaveErrorCode.CommandSendFailed, "Command failed to send"));
            }
        }
    }

    private void EnsurePortOpened()
    {
        if (_commLock.CurrentCount != 0)
        {
            throw new InvalidOperationException("The lock must be held before calling this method");
        }

        if (!_serialPort.IsOpen)
        {
            int retryCount = 0;
            while (true)
            {
                try
                {
                    _serialPort.Open();
                    _logger.LogSerialApiPortReopened(_serialPort.PortName);
                    break;
                }
                catch (FileNotFoundException)
                {
                    // If the port goes away momentarily, for example during a soft reset, retry opening the port a few times
                    if (retryCount <= MaxConnectionAttempts)
                    {
                        retryCount++;
                        Thread.Sleep(ConnectionDelay);
                    }
                    else
                    {
                        throw;
                    }
                }
            }
        }
    }

    private void SendFrame(Frame frame)
    {
        _serialPort.BaseStream.Write(frame.Data.Span);
        _logger.LogSerialApiFrameSent(frame);
    }
}
