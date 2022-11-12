using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using ZWave.CommandClasses;
using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave;

public sealed class Driver : IAsyncDisposable
{
    private record struct AwaitedFrameResponse(CommandId CommandId, TaskCompletionSource<DataFrame> TaskCompletionSource);

    private record struct UnresolvedCallbackKey(CommandId CommandId, byte SessionId);

    private readonly ILogger _logger;

    private readonly ChannelWriter<DataFrameTransmission> _dataFrameSendChannelWriter;

    private readonly ZWaveSerialPortCoordinator _serialPortCoordinator;

    private readonly Task _frameProcessingTask;

    // Lock anything related to session ids or callbacks
    private readonly object _callbackLock = new object();

    private readonly Dictionary<UnresolvedCallbackKey, TaskCompletionSource<DataFrame>> _unresolvedCallbacks = new Dictionary<UnresolvedCallbackKey, TaskCompletionSource<DataFrame>>();

    private byte _lastSessionId = 0;

    // Lock access to _awaitedFrameResponse
    private readonly object _requestResponseFrameFlowLock = new object();

    private AwaitedFrameResponse? _awaitedFrameResponse;

    // Currenty this is the only non-callback request we wait on. If there are more, this should become a pattern.
    private TaskCompletionSource<SerialApiStartedRequest>? _serialApiStartedTaskCompletionSource;

    private Driver(ILogger logger, string portName)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        if (string.IsNullOrEmpty(portName))
        {
            throw new ArgumentNullException(nameof(portName));
        }

        // We can assume a single reader based on the implementation of the serial port coordinator. The writer is the driver, which may be called by multiple callers.
        Channel<DataFrameTransmission> dataFrameSendChannel = Channel.CreateUnbounded<DataFrameTransmission>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });

        // We can assume the single reader/writer based on the implementation of the serial port coordinator and the single frame processing task
        Channel<DataFrame> dataFrameReceiveChannel = Channel.CreateUnbounded<DataFrame>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });

        _serialPortCoordinator = new ZWaveSerialPortCoordinator(logger, portName, dataFrameSendChannel.Reader, dataFrameReceiveChannel.Writer);

        _dataFrameSendChannelWriter = dataFrameSendChannel.Writer;

        // Start a task to asynchronously handle any data frames recieved.
        // Note: Since we're starting out own task, we don't need to ConfigureAwait anywhere dowstream.
        // TODO: Should we consider parallelism here? Perhaps configurable? If so, dataFrameReceiveChannel options needs adjustment
        _frameProcessingTask = Task.Run(
            async () =>
            {
                // Intentionally not passing a cancellation token as the serial port coordinator is responsible to completing the channel.
                await foreach (DataFrame frame in dataFrameReceiveChannel.Reader.ReadAllAsync())
                {
                    try
                    {
                        ProcessDataFrame(frame);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDataFrameProcessingException(ex);
                    }
                }
            });

        Controller = new Controller(logger, this);
    }

    public Controller Controller { get; }

    public static async Task<Driver> CreateAsync(
        ILogger logger,
        string portName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var driver = new Driver(logger, portName);
        await driver.InitializeAsync(cancellationToken).ConfigureAwait(false);
        return driver;
    }

    public async ValueTask DisposeAsync()
    {
        _dataFrameSendChannelWriter.Complete();

        await _serialPortCoordinator.DisposeAsync();

        // Allow the processing task to drain. Disposal of the serial port coordinator should complete the channel.
        await _frameProcessingTask;
    }

    private void ProcessDataFrame(DataFrame frame)
    {
        switch (frame.Type)
        {
            case DataFrameType.REQ:
            {
                // Try handling unsolicited requests first, then check if it's a callback we're waiting for.
                switch (frame.CommandId)
                {
                    case CommandId.SerialApiStarted:
                    {
                        // Unblock the task.
                        if (_serialApiStartedTaskCompletionSource != null)
                        {
                            _serialApiStartedTaskCompletionSource.SetResult(SerialApiStartedRequest.Create(frame));
                        }
                        else
                        {
                            _logger.LogUnexpectedSerialApiStarted();
                        }

                        break;
                    }
                    case CommandId.ApplicationUpdate:
                    {
                        var applicationUpdateRequest = ApplicationUpdateRequest.Create(frame);
                        if (applicationUpdateRequest.Event == ApplicationUpdateEvent.NodeInfoReceived)
                        {
                            if (Controller.Nodes.TryGetValue(applicationUpdateRequest.Generic.NodeId, out Node? node))
                            {
                                node.NotifyNodeInfoReceived(applicationUpdateRequest);
                            }
                            else
                            {
                                _logger.LogUnknownNodeId(applicationUpdateRequest.Generic.NodeId);
                            }
                        }

                        break;
                    }
                    case CommandId.ApplicationCommandHandler:
                    {
                        var applicationCommandHandler = ApplicationCommandHandler.Create(frame);
                        if (Controller.Nodes.TryGetValue(applicationCommandHandler.NodeId, out Node? node))
                        {
                            var commandClassFrame = new CommandClassFrame(applicationCommandHandler.Payload);
                            node.ProcessCommand(commandClassFrame);
                        }
                        else
                        {
                            _logger.LogUnknownNodeId(applicationCommandHandler.NodeId);
                        }

                        break;
                    }
                    default:
                    {
                        // This assumes the first command parameter is always the session id. If this is ever
                        // found not to be the case, we'll need to add the callback index to the key.
                        var callbackKey = new UnresolvedCallbackKey(frame.CommandId, frame.CommandParameters.Span[0]);
                        lock (_callbackLock)
                        {
                            if (_unresolvedCallbacks.TryGetValue(callbackKey, out TaskCompletionSource<DataFrame>? tcs))
                            {
                                tcs.SetResult(frame);
                                _unresolvedCallbacks.Remove(callbackKey);
                                return;
                            }
                        }

                        break;
                    }
                }

                break;
            }
            case DataFrameType.RES:
            {
                // Assign to a local and null out to immediately release the lock safely
                AwaitedFrameResponse? awaitedFrameResponse;
                lock (_requestResponseFrameFlowLock)
                {
                    awaitedFrameResponse = _awaitedFrameResponse;
                    _awaitedFrameResponse = null;
                }

                if (awaitedFrameResponse == null)
                {
                    // We weren't expecting a response. Just drop it
                    _logger.LogUnexpectedResponseFrame(frame);
                    return;
                }

                if (awaitedFrameResponse.Value.CommandId != frame.CommandId)
                {
                    // We weren't expecting this response. Just drop it
                    _logger.LogUnexpectedCommandIdResponseFrame(awaitedFrameResponse.Value.CommandId, frame);
                    return;
                }

                var tcs = awaitedFrameResponse.Value.TaskCompletionSource;
                tcs.SetResult(frame);

                break;
            }
            default:
            {
                // From INS12350 5.4.3
                // A receiving end MUST ignore reserved Type values.
                _logger.LogSerialApiDataFrameUnknownType(frame.Type);
                break;
            }
        }
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _logger.LogDriverInitializing();

        // Perform initialization sequence (INS12350 6.1). Note: ZWaveSerialPortCoordinator sends the NAK upon opening the port.
        try
        {
            await SoftResetAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new ZWaveException(ZWaveErrorCode.DriverInitializationFailed, "Soft reset failed", ex);
        }

        await Controller.IdentifyAsync(cancellationToken).ConfigureAwait(false);

        // Begin interviewing the nodes, starting with and waiting for the controller node
        Node controllerNode = Controller.Nodes[Controller.NodeId];
        await controllerNode.InterviewAsync(cancellationToken).ConfigureAwait(false);

        // This is intentionally fire-and-forget
        _ = Task.Run(async () =>
        {
            foreach (KeyValuePair<byte, Node> pair in Controller.Nodes)
            {
                Node node = pair.Value;
                if (node != controllerNode)
                {
                    try
                    {
                        await node.InterviewAsync(cancellationToken);
                    }
                    catch (Exception)
                    {
                        // TODO: Log
                    }
                }
            }
        });

        _logger.LogDriverInitialized();
    }

    public async Task SoftResetAsync(CancellationToken cancellationToken)
    {
        _logger.LogSoftReset();
        var softResetRequest = SoftResetRequest.Create();
        await SendCommandAsync(softResetRequest, cancellationToken)
            .ConfigureAwait(false);

        _serialApiStartedTaskCompletionSource = new TaskCompletionSource<SerialApiStartedRequest>();
        try
        {
            // Wait for 1.5s per spec, unless we get an affirmative signal back that the serial API has started.
            TimeSpan serialApiStartedWaitTime = TimeSpan.FromMilliseconds(1500);

            SerialApiStartedRequest serialApiStartedRequest = await _serialApiStartedTaskCompletionSource.Task
                .WaitAsync(serialApiStartedWaitTime, cancellationToken)
                .ConfigureAwait(false);

            // TODO: Log wakeup reason and maybe other things
            // TODO: Do something with the response
            return;
        }
        catch (TimeoutException)
        {
            // If we don't get the signal, assume the soft reset was successful after the wait time.
        }
        finally
        {
            _serialApiStartedTaskCompletionSource = null;
        }
    }

    internal byte GetNextSessionId()
    {
        lock (_callbackLock)
        {
            byte nextSessionId = _lastSessionId;

            bool IsSessionIdInUse(byte sessionId)
            {
                foreach (KeyValuePair<UnresolvedCallbackKey, TaskCompletionSource<DataFrame>> pair in _unresolvedCallbacks)
                {
                    if (pair.Key.SessionId == sessionId)
                    {
                        return true;
                    }
                }

                return false;
            }

            // Avoid 0 which indicates disablement of the callback functionality, as well as sessions currently in use.
            do
            {
                nextSessionId++;
            }
            while (nextSessionId == 0 || IsSessionIdInUse(nextSessionId));

            _lastSessionId = nextSessionId;
            return nextSessionId;
        }
    }

    // TODO: This name is terrible. Consider doing more type magic for req/res vs callback flow
    internal async Task<TCallback> SendCommandExpectingCallbackAsync<TRequest, TCallback>(
        TRequest request,
        CancellationToken cancellationToken)
        where TRequest : struct, IRequestWithCallback<TRequest>
        where TCallback : struct, ICommand<TCallback>
    {
        byte sessionId = request.SessionId;

        if (TRequest.ExpectsResponseStatus)
        {
            ResponseStatusResponse response = await SendCommandAsync<TRequest, ResponseStatusResponse>(request, cancellationToken)
                .ConfigureAwait(false);
            if (!response.WasRequestAccepted)
            {
                throw new ZWaveException(ZWaveErrorCode.CommandFailed, "Response status indicated failure");
            }
        }
        else
        {
            await SendCommandAsync(request, cancellationToken)
                .ConfigureAwait(false);
        }

        TaskCompletionSource<DataFrame> tcs = new TaskCompletionSource<DataFrame>();
        var callbackKey = new UnresolvedCallbackKey(TCallback.CommandId, sessionId);
        lock (_callbackLock)
        {
            _unresolvedCallbacks.Add(callbackKey, tcs);
        }

        DataFrame callbackFrame = await tcs.Task;
        return TCallback.Create(callbackFrame);
    }

    internal async Task<TResponse> SendCommandAsync<TRequest, TResponse>(
        TRequest request,
        CancellationToken cancellationToken)
        where TRequest : struct, ICommand<TRequest>
        where TResponse : struct, ICommand<TResponse>
    {
        var tcs = new TaskCompletionSource<DataFrame>();

        // INS12350 6.5.2 due to the simple nature of the simple acknowledge mechanism, only one REQ->RES session is allowed.
        // Based on this, if there is an existing request which requires an immediate response, this new one needs to wait until
        // the previous one finishes.
        while (true)
        {
            TaskCompletionSource<DataFrame> existingFrameFlowTcs;
            lock (_requestResponseFrameFlowLock)
            {
                if (_awaitedFrameResponse == null)
                {
                    _awaitedFrameResponse = new AwaitedFrameResponse(request.Frame.CommandId, tcs);
                    break;
                }
                else
                {
                    existingFrameFlowTcs = _awaitedFrameResponse.Value.TaskCompletionSource;
                }
            }

            await existingFrameFlowTcs.Task;
        }

        await SendFrameAsync(request.Frame, cancellationToken).ConfigureAwait(false);

        DataFrame responseFrame = await tcs.Task.WaitAsync(cancellationToken);

        return TResponse.Create(responseFrame);
    }

    internal async Task SendCommandAsync<TRequest>(
        TRequest request,
        CancellationToken cancellationToken)
        where TRequest : struct, ICommand<TRequest>
        => await SendFrameAsync(request.Frame, cancellationToken).ConfigureAwait(false);

    internal async Task SendCommandAsync<TCommand>(
        TCommand request,
        byte nodeId,
        CancellationToken cancellationToken)
        where TCommand : struct, ICommand
    {
        const TransmissionOptions transmissionOptions = TransmissionOptions.ACK | TransmissionOptions.AutoRoute | TransmissionOptions.Explore;
        byte sessionId = GetNextSessionId();
        SendDataRequest sendDataRequest = SendDataRequest.Create(nodeId, request.Frame.Data.Span, transmissionOptions, sessionId);
        ResponseStatusResponse response = await SendCommandAsync<SendDataRequest, ResponseStatusResponse>(sendDataRequest, cancellationToken)
            .ConfigureAwait(false);
        if (!response.WasRequestAccepted)
        {
            throw new ZWaveException(ZWaveErrorCode.CommandFailed, "Response status indicated failure");
        }

        TaskCompletionSource<DataFrame> tcs = new TaskCompletionSource<DataFrame>();
        var callbackKey = new UnresolvedCallbackKey(CommandId.SendData, sessionId);
        lock (_callbackLock)
        {
            _unresolvedCallbacks.Add(callbackKey, tcs);
        }

        // Intentionally not awaiting this task. The callback only contains a transmit report,
        // which the caller doesn't care about.
        _ = tcs.Task.ContinueWith(task =>
        {
            // The unresolved callback tasks currently never get cancelled or fault. If this changes,
            // consider what to do here in those cases.
            if (task.IsCompletedSuccessfully)
            {
                DataFrame callbackFrame = task.Result;
                SendDataCallback callback = SendDataCallback.Create(callbackFrame);

                // TODO: Consume the transmit report.
            }
        });
    }

    private async Task SendFrameAsync(DataFrame request, CancellationToken cancellationToken)
    {
        var transmissionComplete = new TaskCompletionSource();
        var transmission = new DataFrameTransmission(request, transmissionComplete);

        await _dataFrameSendChannelWriter.WriteAsync(transmission, cancellationToken).ConfigureAwait(false);

        // Wait until the frame is sent.
        await transmissionComplete.Task;
    }
}
