using ZWave.Serial.Commands;

namespace ZWave.CommandClasses;

public enum Powerlevel : byte
{
    Normal = 0x00,

    Minus1dBm = 0x01,

    Minus2dBm = 0x02,

    Minus3dBm = 0x03,

    Minus4dBm = 0x04,

    Minus5dBm = 0x05,

    Minus6dBm = 0x06,

    Minus7dBm = 0x07,

    Minus8dBm = 0x08,

    Minus9dBm = 0x09,
}

public enum PowerlevelTestStatus : byte
{
    /// <summary>
    /// No frame was returned during the test
    /// </summary>
    Failed = 0x00,

    /// <summary>
    /// At least 1 frame was returned during the test
    /// </summary>
    Success = 0x01,

    /// <summary>
    /// The test is still ongoing
    /// </summary>
    InProgress = 0x02,
}

public enum PowerlevelCommand : byte
{
    /// <summary>
    /// Set the power level indicator value, which should be used by the node when transmitting RF.
    /// </summary>
    Set = 0x01,

    /// <summary>
    /// Request the current power level value.
    /// </summary>
    Get = 0x02,

    /// <summary>
    /// Advertise the current power level.
    /// </summary>
    Report = 0x03,

    /// <summary>
    /// Instruct the destination node to transmit a number of test frames to the specified NodeID with the RF
    /// power level specified.
    /// </summary>
    TestNodeSet = 0x04,

    /// <summary>
    /// Request the result of the latest Powerlevel Test
    /// </summary>
    TestNodeGet = 0x05,

    /// <summary>
    /// Report the latest result of a test frame transmission started by the Powerlevel Test Node Set Command.
    /// </summary>
    TestNodeReport = 0x06,
}

public readonly struct PowerlevelState
{
    public PowerlevelState(Powerlevel powerlevel, byte? timeoutInSeconds)
    {
        Powerlevel = powerlevel;
        TimeoutInSeconds = timeoutInSeconds;
    }

    /// <summary>
    /// The current power level indicator value in effect on the node
    /// </summary>
    public Powerlevel Powerlevel { get; }

    /// <summary>
    /// The time in seconds the node has back at Power level before resetting to normal Power level.
    /// </summary>
    /// <remarks>
    /// May be null when <see cref="Powerlevel"/> is <see cref="Powerlevel.Normal"/>.
    /// </remarks>
    public byte? TimeoutInSeconds { get; }
}

public readonly struct PowerlevelTestResult
{
    public PowerlevelTestResult(byte nodeId, PowerlevelTestStatus status, ushort frameAcknowledgedCount)
    {
        NodeId = nodeId;
        Status = status;
        FrameAcknowledgedCount = frameAcknowledgedCount;
    }

    /// <summary>
    /// The node ID of the node which is or has been under test.
    /// </summary>
    public byte NodeId { get; }

    /// <summary>
    /// The result of the test
    /// </summary>
    public PowerlevelTestStatus Status { get;}

    /// <summary>
    /// The number of test frames transmitted which the Test NodeID has acknowledged.
    /// </summary>
    public ushort FrameAcknowledgedCount { get; }
}

[CommandClass(CommandClassId.Powerlevel)]
public sealed class PowerlevelCommandClass : CommandClass<PowerlevelCommand>
{
    public PowerlevelCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public PowerlevelState? State { get; private set; }

    public PowerlevelTestResult? LastTestResult { get; private set; }

    public override bool? IsCommandSupported(PowerlevelCommand command) => true;

    /// <summary>
    /// Set the power level indicator value, which should be used by the node when transmitting RF.
    /// </summary>
    /// <param name="powerlevel">
    /// The power level indicator value, which should be used by the node when transmitting RF.
    /// </param>
    /// <param name="timeoutInSeconds">
    /// The timeout in seconds for this power level indicator value before returning the power level defined by
    /// the application. Must be non-zero unless the power level is <see cref="Powerlevel.Normal"/>.
    /// </param>
    public async Task SetAsync(
        Powerlevel powerlevel,
        byte timeoutInSeconds,
        CancellationToken cancellationToken)
    {
        if (timeoutInSeconds == 0 && powerlevel != Powerlevel.Normal)
        {
            throw new ArgumentException("Timeout must be non-zero", nameof(timeoutInSeconds));
        }

        var command = PowerlevelSetCommand.Create(powerlevel, timeoutInSeconds);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request the current power level value.
    /// </summary>
    public async Task<PowerlevelState> GetAsync(CancellationToken cancellationToken)
    {
        var command = PowerlevelGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<PowerlevelReportCommand>(cancellationToken).ConfigureAwait(false);
        return State!.Value;
    }

    /// <summary>
    /// Instruct the destination node to transmit a number of test frames to the specified NodeID with the RF
    /// power level specified.
    /// </summary>
    public async Task<PowerlevelTestResult> TestNodeAsync(
        byte testNodeId,
        Powerlevel powerlevel,
        ushort testFrameCount,
        CancellationToken cancellationToken)
    {
        if (testNodeId == Node.Id)
        {
            throw new ArgumentException("The test node must be different from the node performing the test.", nameof(testNodeId));
        }

        if (!Driver.Controller.Nodes.TryGetValue(testNodeId, out Node? testNode))
        {
            throw new ArgumentException($"The test node {testNodeId} does not exist.", nameof(testNodeId));
        }

        if (testNode.FrequentListeningMode != FrequentListeningMode.None)
        {
            throw new ZWaveException(
                ZWaveErrorCode.CommandInvalidArgument,
                $"The test node {testNodeId} is FLiRS and cannot be used for a Powerlevel test");
        }

        // TODO: Throw if test node is sleeping

        var command = PowerlevelTestNodeSetCommand.Create(testNodeId, powerlevel, testFrameCount);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<PowerlevelTestNodeReportCommand>(cancellationToken).ConfigureAwait(false);
        return LastTestResult!.Value;
    }

    /// <summary>
    /// Request the result of the latest Powerlevel Test
    /// </summary>
    public async Task<PowerlevelTestResult?> GetLastTestResultsAsync(CancellationToken cancellationToken)
    {
        var command = PowerlevelTestNodeGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<PowerlevelTestNodeReportCommand>(cancellationToken).ConfigureAwait(false);
        return LastTestResult;
    }

    internal override Task InterviewAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((PowerlevelCommand)frame.CommandId)
        {
            case PowerlevelCommand.Set:
            case PowerlevelCommand.Get:
            case PowerlevelCommand.TestNodeSet:
            case PowerlevelCommand.TestNodeGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case PowerlevelCommand.Report:
            {
                var command = new PowerlevelReportCommand(frame);
                State = new PowerlevelState(command.Powerlevel, command.TimeoutInSeconds);
                break;
            }
            case PowerlevelCommand.TestNodeReport:
            {
                var command = new PowerlevelTestNodeReportCommand(frame);
                if (command.TestNodeId.HasValue)
                {
                    LastTestResult = new PowerlevelTestResult(
                        command.TestNodeId.Value,
                        command.TestStatus!.Value,
                        command.TestFrameAcknowledgedCount!.Value);
                }
                else
                {
                    // If we got a report with no results, clear the value to avoid confusion.
                    LastTestResult = null;
                }

                break;
            }
        }
    }

    private struct PowerlevelSetCommand : ICommand
    {
        public PowerlevelSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.Set;

        public CommandClassFrame Frame { get; }

        public static PowerlevelSetCommand Create(Powerlevel powerlevel, byte timeoutInSeconds)
        {
            Span<byte> commandParameters = stackalloc byte[2];
            commandParameters[0] = (byte)powerlevel;
            commandParameters[1] = timeoutInSeconds;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new PowerlevelSetCommand(frame);
        }
    }

    private struct PowerlevelGetCommand : ICommand
    {
        public PowerlevelGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.Get;

        public CommandClassFrame Frame { get; }

        public static PowerlevelSetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new PowerlevelSetCommand(frame);
        }
    }

    private struct PowerlevelReportCommand : ICommand
    {
        public PowerlevelReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The current power level indicator value in effect on the node
        /// </summary>
        public Powerlevel Powerlevel => (Powerlevel)Frame.CommandParameters.Span[0];

        /// <summary>
        /// The time in seconds the node has back at Power level before resetting to normal Power level.
        /// </summary>
        public byte? TimeoutInSeconds => Powerlevel != Powerlevel.Normal
            ? Frame.CommandParameters.Span[1]
            : null;
    }

    private struct PowerlevelTestNodeSetCommand : ICommand
    {
        public PowerlevelTestNodeSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.TestNodeSet;

        public CommandClassFrame Frame { get; }

        public static PowerlevelSetCommand Create(
            byte testNodeId,
            Powerlevel powerlevel,
            ushort testFrameCount)
        {
            Span<byte> commandParameters = stackalloc byte[4];
            commandParameters[0] = testNodeId;
            commandParameters[1] = (byte)powerlevel;
            testFrameCount.WriteBytesBE(commandParameters[2..4]);

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new PowerlevelSetCommand(frame);
        }
    }

    private struct PowerlevelTestNodeGetCommand : ICommand
    {
        public PowerlevelTestNodeGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.TestNodeGet;

        public CommandClassFrame Frame { get; }

        public static PowerlevelTestNodeGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new PowerlevelTestNodeGetCommand(frame);
        }
    }

    private struct PowerlevelTestNodeReportCommand : ICommand
    {
        public PowerlevelTestNodeReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Powerlevel;

        public static byte CommandId => (byte)PowerlevelCommand.TestNodeReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The node ID of the node which is or has been under test.
        /// </summary>
        public byte? TestNodeId
        {
            get
            {
                byte nodeId = Frame.CommandParameters.Span[0];
                return nodeId == 0 ? null : nodeId;
            }
        }

        /// <summary>
        /// The result of the last test initiated with the Powerlevel Test Node Set Command
        /// </summary>
        public PowerlevelTestStatus? TestStatus => TestNodeId.HasValue
            ? (PowerlevelTestStatus)Frame.CommandParameters.Span[1]
            : null;

        /// <summary>
        /// The number of test frames transmitted which the Test NodeID has acknowledged.
        /// </summary>
        public ushort? TestFrameAcknowledgedCount => TestNodeId.HasValue
            ? Frame.CommandParameters.Span[2..4].ToUInt16BE()
            : null;
    }
}
