namespace ZWave.CommandClasses;

public enum WakeUpCommand : byte
{
    /// <summary>
    /// Configure the Wake Up interval and destination of a node.
    /// </summary>
    IntervalSet = 0x04,

    /// <summary>
    /// Request the Wake Up Interval and destination of a node.
    /// </summary>
    IntervalGet = 0x05,

    /// <summary>
    /// Advertise the current Wake Up interval and destination.
    /// </summary>
    IntervalReport = 0x06,

    /// <summary>
    /// Indicates that a node is awake.
    /// </summary>
    Notification = 0x07,

    /// <summary>
    /// Notify a supporting node that it may return to sleep to minimize power consumption.
    /// </summary>
    NoMoreInformation = 0x08,

    /// <summary>
    /// Request the Wake Up Interval capabilities of a node.
    /// </summary>
    IntervalCapabilitiesGet = 0x09,

    /// <summary>
    /// Advertise the Wake Up Interval capabilities of a node.
    /// </summary>
    IntervalCapabilitiesReport = 0x0a,
}

public readonly struct WakeUpInterval
{
    public WakeUpInterval(
        uint wakeupIntervalInSeconds,
        uint wakeupDestinationNodeId)
    {
        WakeupIntervalInSeconds = wakeupIntervalInSeconds;
        WakeupDestinationNodeId = wakeupDestinationNodeId;
    }

    /// <summary>
    /// The time in seconds between Wake Up periods at the sending node
    /// </summary>
    public uint WakeupIntervalInSeconds { get; }

    /// <summary>
    /// The Wake Up destination NodeID configured at the sending node
    /// </summary>
    public uint WakeupDestinationNodeId { get; }
}

public readonly struct WakeUpIntervalCapabilities
{
    public WakeUpIntervalCapabilities(
        uint minimumWakeupIntervalInSeconds,
        uint maximumWakeupIntervalInSeconds,
        uint defaultWakeupIntervalInSeconds,
        uint wakeupIntervalStepInSeconds,
        bool? supportsWakeUpOnDemand)
    {
        MinimumWakeupIntervalInSeconds = minimumWakeupIntervalInSeconds;
        MaximumWakeupIntervalInSeconds = maximumWakeupIntervalInSeconds;
        DefaultWakeupIntervalInSeconds = defaultWakeupIntervalInSeconds;
        WakeupIntervalStepInSeconds = wakeupIntervalStepInSeconds;
        SupportsWakeUpOnDemand = supportsWakeUpOnDemand;
    }

    /// <summary>
    /// The minimum Wake Up Interval supported by the sending node
    /// </summary>
    public uint MinimumWakeupIntervalInSeconds { get; }

    /// <summary>
    /// The maximum Wake Up Interval supported by the sending node
    /// </summary>
    public uint MaximumWakeupIntervalInSeconds { get; }

    /// <summary>
    /// The default Wake Up Interval for the sending node
    /// </summary>
    public uint DefaultWakeupIntervalInSeconds { get; }

    /// <summary>
    /// The resolution of valid Wake Up Intervals values for the sending node.
    /// </summary>
    public uint WakeupIntervalStepInSeconds { get; }

    /// <summary>
    /// Whther the supporting node supports the Wake Up On Demand functionality
    /// </summary>
    public bool? SupportsWakeUpOnDemand { get; }

}

[CommandClass(CommandClassId.WakeUp)]
public sealed class WakeUpCommandClass : CommandClass<WakeUpCommand>
{
    public WakeUpCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public WakeUpInterval? Interval { get; private set; }

    public WakeUpIntervalCapabilities? IntervalCapabilities { get; private set; }

    public override bool? IsCommandSupported(WakeUpCommand command)
        => command switch
        {
            WakeUpCommand.IntervalGet => true,
            WakeUpCommand.IntervalSet => true,
            WakeUpCommand.NoMoreInformation => true,
            WakeUpCommand.IntervalCapabilitiesGet => Version.HasValue ? Version >= 2 : null,
            _ => false,
        };

    /// <summary>
    /// Request the Wake Up Interval and destination of a node.
    /// </summary>
    public async Task<WakeUpInterval> GetIntervalAsync(CancellationToken cancellationToken)
    {
        var command = WakeUpIntervalGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<WakeUpIntervalReportCommand>(cancellationToken).ConfigureAwait(false);
        return Interval!.Value;
    }

    /// <summary>
    /// Configure the Wake Up interval and destination of a node.
    /// </summary>
    public async Task SetIntervalAsync(uint wakeupIntervalInSeconds, byte wakeupDestinationNodeId, CancellationToken cancellationToken)
    {
        var command = WakeUpIntervalSetCommand.Create(wakeupIntervalInSeconds, wakeupDestinationNodeId);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    public async Task<WakeUpIntervalCapabilities> GetIntervalCapabilitiesAsync(CancellationToken cancellationToken)
    {
        var command = WakeUpIntervalCapabilitiesGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<WakeUpIntervalCapabilitiesReportCommand>(cancellationToken).ConfigureAwait(false);
        return IntervalCapabilities!.Value;
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        _ = await GetIntervalAsync(cancellationToken).ConfigureAwait(false);

        if (IsCommandSupported(WakeUpCommand.IntervalCapabilitiesGet).GetValueOrDefault())
        {
            _ = await GetIntervalCapabilitiesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((WakeUpCommand)frame.CommandId)
        {
            case WakeUpCommand.IntervalGet:
            case WakeUpCommand.IntervalSet:
            case WakeUpCommand.NoMoreInformation:
            case WakeUpCommand.IntervalCapabilitiesGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case WakeUpCommand.IntervalReport:
            {
                var command = new WakeUpIntervalReportCommand(frame);
                Interval = new WakeUpInterval(command.WakeupIntervalInSeconds, command.WakeupDestinationNodeId);
                break;
            }
            case WakeUpCommand.Notification:
            {
                // TODO: Manage node asleep/awake
                _ = new WakeUpNotificationCommand(frame);
                break;
            }
            case WakeUpCommand.IntervalCapabilitiesReport:
            {
                var command = new WakeUpIntervalCapabilitiesReportCommand(frame, EffectiveVersion);
                IntervalCapabilities = new WakeUpIntervalCapabilities(
                    command.MinimumWakeupIntervalInSeconds,
                    command.MaximumWakeupIntervalInSeconds,
                    command.DefaultWakeupIntervalInSeconds,
                    command.WakeupIntervalStepInSeconds,
                    command.SupportsWakeUpOnDemand);
                break;
            }
        }
    }

    private struct WakeUpIntervalSetCommand : ICommand
    {
        public WakeUpIntervalSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.IntervalSet;

        public CommandClassFrame Frame { get; }

        public static WakeUpIntervalSetCommand Create(uint wakeupIntervalInSeconds, byte wakeupDestinationNodeId)
        {
            Span<byte> commandParameters = stackalloc byte[4];

            // The parameter is a 24-bit value, which .NET doesn't have built-in types for. So use a uint (32-bit),
            // convert to bytes, and ignore byte 0 (since this is a big-endian value)
            const int int24MaxValue = (1 << 24) - 1;
            if (wakeupIntervalInSeconds > int24MaxValue)
            {
                throw new ArgumentException($"Value must not be greater than {int24MaxValue}", nameof(wakeupIntervalInSeconds));
            }

            Span<byte> secondsBytes = stackalloc byte[4];
            wakeupIntervalInSeconds.WriteBytesBE(secondsBytes);
            secondsBytes[1..].CopyTo(commandParameters);

            commandParameters[3] = wakeupDestinationNodeId;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new WakeUpIntervalSetCommand(frame);
        }
    }

    private struct WakeUpIntervalGetCommand : ICommand
    {
        public WakeUpIntervalGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.IntervalGet;

        public CommandClassFrame Frame { get; }

        public static WakeUpIntervalGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new WakeUpIntervalGetCommand(frame);
        }
    }

    private struct WakeUpIntervalReportCommand : ICommand
    {
        public WakeUpIntervalReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.IntervalReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The time in seconds between Wake Up periods at the sending node
        /// </summary>
        public uint WakeupIntervalInSeconds => Frame.CommandParameters.Span[0..3].ToUInt32BE();

        /// <summary>
        /// The Wake Up destination NodeID configured at the sending node
        /// </summary>
        public uint WakeupDestinationNodeId => Frame.CommandParameters.Span[3];
    }

    private struct WakeUpNotificationCommand : ICommand
    {
        public WakeUpNotificationCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.Notification;

        public CommandClassFrame Frame { get; }
    }

    private struct WakeUpNoMoreInformationCommand : ICommand
    {
        public WakeUpNoMoreInformationCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.NoMoreInformation;

        public CommandClassFrame Frame { get; }

        public static WakeUpIntervalGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new WakeUpIntervalGetCommand(frame);
        }
    }

    private struct WakeUpIntervalCapabilitiesGetCommand : ICommand
    {
        public WakeUpIntervalCapabilitiesGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.IntervalCapabilitiesGet;

        public CommandClassFrame Frame { get; }

        public static WakeUpIntervalGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new WakeUpIntervalGetCommand(frame);
        }
    }

    private struct WakeUpIntervalCapabilitiesReportCommand : ICommand
    {
        private readonly byte _version;

        public WakeUpIntervalCapabilitiesReportCommand(CommandClassFrame frame, byte version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.WakeUp;

        public static byte CommandId => (byte)WakeUpCommand.IntervalCapabilitiesReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The minimum Wake Up Interval supported by the sending node
        /// </summary>
        public uint MinimumWakeupIntervalInSeconds => Frame.CommandParameters.Span[0..3].ToUInt32BE();

        /// <summary>
        /// The maximum Wake Up Interval supported by the sending node
        /// </summary>
        public uint MaximumWakeupIntervalInSeconds => Frame.CommandParameters.Span[3..6].ToUInt32BE();

        /// <summary>
        /// The default Wake Up Interval for the sending node
        /// </summary>
        public uint DefaultWakeupIntervalInSeconds => Frame.CommandParameters.Span[6..9].ToUInt32BE();

        /// <summary>
        /// The resolution of valid Wake Up Intervals values for the sending node.
        /// </summary>
        public uint WakeupIntervalStepInSeconds => Frame.CommandParameters.Span[9..12].ToUInt32BE();

        /// <summary>
        /// Whther the supporting node supports the Wake Up On Demand functionality
        /// </summary>
        public bool? SupportsWakeUpOnDemand => _version >= 3 && Frame.CommandParameters.Length > 12
            ? Frame.CommandParameters.Span[12] == 1
            : null;
    }
}
