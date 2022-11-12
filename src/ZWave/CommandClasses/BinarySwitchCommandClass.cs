namespace ZWave.CommandClasses;

public enum BinarySwitchCommand : byte
{
    /// <summary>
    /// Set the On/Off state at the receiving node.
    /// </summary>
    Set = 0x01,

    /// <summary>
    /// Request the current On/Off state from a node
    /// </summary>
    Get = 0x02,

    /// <summary>
    /// Advertise the current On/Off state at the sending node
    /// </summary>
    Report = 0x03,
}

public readonly struct BinarySwitchState
{
    public BinarySwitchState(
        bool? currentValue,
        bool? targetValue,
        DurationReport? duration)
    {
        CurrentValue = currentValue;
        TargetValue = targetValue;
        Duration = duration;
    }

    /// <summary>
    /// The current On/Off state at the sending node
    /// </summary>
    public bool? CurrentValue { get; }

    /// <summary>
    /// The target value of an ongoing transition or the most recent transition.
    /// </summary>
    public bool? TargetValue { get; }

    /// <summary>
    /// Advertise the duration of a transition from the Current Value to the Target Value.
    /// </summary>
    public DurationReport? Duration { get; }
}

[CommandClass(CommandClassId.BinarySwitch)]
public sealed class BinarySwitchCommandClass : CommandClass<BinarySwitchCommand>
{
    internal BinarySwitchCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public BinarySwitchState? State { get; private set; }

    /// <inheritdoc />
    public override bool? IsCommandSupported(BinarySwitchCommand command)
        => command switch
        {
            BinarySwitchCommand.Set => true,
            BinarySwitchCommand.Get => true,
            _ => false,
        };

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        _ = await GetAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request the current On/Off state from a node
    /// </summary>
    public async Task<BinarySwitchState> GetAsync(CancellationToken cancellationToken)
    {
        var command = BinarySwitchGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<BinarySwitchReportCommand>(cancellationToken).ConfigureAwait(false);
        return State!.Value;
    }

    /// <summary>
    /// Set the On/Off state at the receiving node.
    /// </summary>
    public async Task SetAsync(
        bool targetValue,
        DurationSet? duration,
        CancellationToken cancellationToken)
    {
        var command = BinarySwitchSetCommand.Create(EffectiveVersion, targetValue, duration);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((BinarySwitchCommand)frame.CommandId)
        {
            case BinarySwitchCommand.Set:
            case BinarySwitchCommand.Get:
            {
                // We don't expect to recieve these commands
                break;
            }
            case BinarySwitchCommand.Report:
            {
                var command = new BinarySwitchReportCommand(frame, EffectiveVersion);
                State = new BinarySwitchState(
                    command.CurrentValue,
                    command.TargetValue,
                    command.Duration);
                break;
            }
        }
    }

    private struct BinarySwitchSetCommand : ICommand
    {
        public BinarySwitchSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySwitch;

        public static byte CommandId => (byte)BinarySwitchCommand.Set;

        public CommandClassFrame Frame { get; }

        public static BinarySwitchSetCommand Create(byte version, bool value, DurationSet? duration)
        {
            bool includeDuration = version >= 2 && duration.HasValue;
            Span<byte> commandParameters = stackalloc byte[1 + (includeDuration ? 1 : 0)];
            commandParameters[0] = value ? (byte)0xff : (byte)0x00;
            if (includeDuration)
            {
                commandParameters[1] = duration!.Value.Value;
            }

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new BinarySwitchSetCommand(frame);
        }
    }

    private struct BinarySwitchGetCommand : ICommand
    {
        public BinarySwitchGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySwitch;

        public static byte CommandId => (byte)BinarySwitchCommand.Get;

        public CommandClassFrame Frame { get; }

        public static BinarySwitchGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new BinarySwitchGetCommand(frame);
        }
    }

    private struct BinarySwitchReportCommand : ICommand
    {
        private readonly byte _version;

        public BinarySwitchReportCommand(CommandClassFrame frame, byte version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySwitch;

        public static byte CommandId => (byte)BinarySwitchCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The current On/Off state at the sending node
        /// </summary>
        public bool? CurrentValue => ParseBool(Frame.CommandParameters.Span[0]);

        /// <summary>
        /// The target value of an ongoing transition or the most recent transition.
        /// </summary>
        public bool? TargetValue => _version >= 2 && Frame.CommandParameters.Length > 1
            ? ParseBool(Frame.CommandParameters.Span[1])
            : null;

        /// <summary>
        /// The time needed to reach the Target Value at the actual transition rate.
        /// </summary>
        public DurationReport? Duration => _version >= 2 && Frame.CommandParameters.Length > 2
            ? Frame.CommandParameters.Span[2]
            : null;

        private static bool? ParseBool(byte b)
            => b switch
            {
                0x00 => false,
                0xff => true,
                _ => null,
            };
    }
}
