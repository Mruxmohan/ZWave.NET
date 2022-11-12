namespace ZWave.CommandClasses;

public enum ColorSwitchColorComponent : byte
{
    WarmWhite = 0x00,

    ColdWhite = 0x01,

    Red = 0x02,

    Green = 0x03,

    Blue = 0x04,

    Amber = 0x05,

    Cyan = 0x06,

    Purple = 0x07,

    Index = 0x08,
}

public enum ColorSwitchChangeDirection : byte
{
    Up = 0x00,

    Down = 0x01,
}

public enum ColorSwitchCommand : byte
{
    /// <summary>
    /// Request the supported color components of a device
    /// </summary>
    SupportedGet = 0x01,

    /// <summary>
    /// Report the supported color components of a device
    /// </summary>
    SupportedReport = 0x02,

    /// <summary>
    /// Request the status of a specified color component
    /// </summary>
    Get = 0x03,

    Report = 0x04,

    Set = 0x05,

    StartLevelChange = 0x06,

    StopLevelChange = 0x07,
}

public readonly struct ColorSwitchColorComponentState
{
    public ColorSwitchColorComponentState(
        byte currentValue,
        byte? targetValue,
        DurationReport? duration)
    {
        CurrentValue = currentValue;
        TargetValue = targetValue;
        Duration = duration;
    }

    /// <summary>
    /// The current value of the color component identified by the Color Component ID
    /// </summary>
    public byte CurrentValue { get; }

    /// <summary>
    /// The target value of an ongoing transition or the most recent transition for the advertised Color Component ID.
    /// </summary>
    public byte? TargetValue { get; }

    /// <summary>
    /// The time needed to reach the Target Value at the actual transition rate.
    /// </summary>
    public DurationReport? Duration { get; }
}

[CommandClass(CommandClassId.ColorSwitch)]
public sealed class ColorSwitchCommandClass : CommandClass<ColorSwitchCommand>
{
    private Dictionary<ColorSwitchColorComponent, ColorSwitchColorComponentState?>? _colorComponents;

    public ColorSwitchCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    /// <summary>
    /// The color components supported by the device
    /// </summary>
    public IReadOnlySet<ColorSwitchColorComponent>? SupportedComponents { get; private set; }

    /// <summary>
    /// The state of the color components supported by the device
    /// </summary>
    public IReadOnlyDictionary<ColorSwitchColorComponent, ColorSwitchColorComponentState?>? ColorComponents => _colorComponents;

    public override bool? IsCommandSupported(ColorSwitchCommand command)
        => command switch
        {
            ColorSwitchCommand.SupportedGet => true,
            ColorSwitchCommand.Get => true,
            ColorSwitchCommand.Set => true,
            ColorSwitchCommand.StartLevelChange => true,
            ColorSwitchCommand.StopLevelChange => true,
            _ => false,
        };

    public async Task<IReadOnlySet<ColorSwitchColorComponent>> GetSupportedAsync(CancellationToken cancellationToken)
    {
        var command = ColorSwitchSupportedGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<ColorSwitchSupportedReportCommand>(cancellationToken).ConfigureAwait(false);
        return SupportedComponents!;
    }

    public async Task<ColorSwitchColorComponentState> GetAsync(
        ColorSwitchColorComponent colorComponent,
        CancellationToken cancellationToken)
    {
        var command = ColorSwitchGetCommand.Create(colorComponent);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<ColorSwitchReportCommand>(cancellationToken).ConfigureAwait(false);
        return ColorComponents![colorComponent]!.Value;
    }

    public async Task SetAsync(
        IReadOnlyDictionary<ColorSwitchColorComponent, byte> values,
        DurationSet? duration,
        CancellationToken cancellationToken)
    {
        var command = ColorSwitchSetCommand.Create(EffectiveVersion, values, duration);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    public async Task StartLevelChangeAsync(
        ColorSwitchChangeDirection direction,
        ColorSwitchColorComponent colorComponent,
        byte? startLevel,
        DurationSet? duration,
        CancellationToken cancellationToken)
    {
        var command = ColorSwitchStartLevelChangeCommand.Create(
            EffectiveVersion,
            direction,
            colorComponent,
            startLevel,
            duration);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    public async Task StopLevelChangeAsync(ColorSwitchColorComponent colorComponent, CancellationToken cancellationToken)
    {
        var command = ColorSwitchStopLevelChangeCommand.Create(colorComponent);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        IReadOnlySet<ColorSwitchColorComponent> supportedColorComponents = await GetSupportedAsync(cancellationToken).ConfigureAwait(false);

        foreach (var colorComponent in supportedColorComponents)
        {
            _ = await GetAsync(colorComponent, cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((ColorSwitchCommand)frame.CommandId)
        {
            case ColorSwitchCommand.SupportedGet:
            case ColorSwitchCommand.Get:
            case ColorSwitchCommand.Set:
            case ColorSwitchCommand.StartLevelChange:
            case ColorSwitchCommand.StopLevelChange:
            {
                // We don't expect to recieve these commands
                break;
            }
            case ColorSwitchCommand.SupportedReport:
            {
                var command = new ColorSwitchSupportedReportCommand(frame);
                SupportedComponents = command.SupportedComponents;

                var newColorComponents = new Dictionary<ColorSwitchColorComponent, ColorSwitchColorComponentState?>();
                foreach (ColorSwitchColorComponent colorComponent in SupportedComponents)
                {
                    // Persist any existing known state.
                    if (ColorComponents == null
                        || !ColorComponents.TryGetValue(colorComponent, out ColorSwitchColorComponentState? colorComponentState))
                    {
                        colorComponentState = null;
                    }

                    newColorComponents.Add(colorComponent, colorComponentState);
                }

                _colorComponents = newColorComponents;

                break;
            }
            case ColorSwitchCommand.Report:
            {
                var command = new ColorSwitchReportCommand(frame, EffectiveVersion);
                _colorComponents![command.ColorComponent] = new ColorSwitchColorComponentState(
                    command.CurrentValue,
                    command.TargetValue,
                    command.Duration);
                break;
            }
        }
    }

    private struct ColorSwitchSupportedGetCommand : ICommand
    {
        public ColorSwitchSupportedGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.SupportedGet;

        public CommandClassFrame Frame { get; }

        public static ColorSwitchSupportedGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new ColorSwitchSupportedGetCommand(frame);
        }
    }

    private struct ColorSwitchSupportedReportCommand : ICommand
    {
        public ColorSwitchSupportedReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.SupportedReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The color components supported by the device
        /// </summary>
        public IReadOnlySet<ColorSwitchColorComponent> SupportedComponents
        {
            get
            {
                var supportedComponents = new HashSet<ColorSwitchColorComponent>();

                ReadOnlySpan<byte> bitMask = Frame.CommandParameters.Span.Slice(0, 2);
                for (int byteNum = 0; byteNum < bitMask.Length; byteNum++)
                {
                    for (int bitNum = 0; bitNum < 8; bitNum++)
                    {
                        if ((bitMask[byteNum] & (1 << bitNum)) != 0)
                        {
                            ColorSwitchColorComponent colorComponent = (ColorSwitchColorComponent)((byteNum << 3) + bitNum);
                            supportedComponents.Add(colorComponent);
                        }
                    }
                }

                return supportedComponents;
            }
        }
    }

    private struct ColorSwitchGetCommand : ICommand
    {
        public ColorSwitchGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.Get;

        public CommandClassFrame Frame { get; }

        public static ColorSwitchGetCommand Create(ColorSwitchColorComponent colorComponent)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = (byte)colorComponent;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new ColorSwitchGetCommand(frame);
        }
    }

    private struct ColorSwitchReportCommand : ICommand
    {
        private readonly byte _version;

        public ColorSwitchReportCommand(CommandClassFrame frame, byte version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The color component covered by this report
        /// </summary>
        public ColorSwitchColorComponent ColorComponent => (ColorSwitchColorComponent)Frame.CommandParameters.Span[0];

        /// <summary>
        /// The current value of the color component identified by the Color Component ID
        /// </summary>
        public byte CurrentValue => Frame.CommandParameters.Span[1];

        /// <summary>
        /// The target value of an ongoing transition or the most recent transition for the advertised Color Component ID.
        /// </summary>
        public byte? TargetValue => _version >= 3 && Frame.CommandParameters.Length > 2
            ? Frame.CommandParameters.Span[2]
            : null;

        /// <summary>
        /// The time needed to reach the Target Value at the actual transition rate.
        /// </summary>
        public DurationReport? Duration => _version >= 3 && Frame.CommandParameters.Length > 3
            ? Frame.CommandParameters.Span[3]
            : null;
    }

    private struct ColorSwitchSetCommand : ICommand
    {
        public ColorSwitchSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.Set;

        public CommandClassFrame Frame { get; }

        public static ColorSwitchSetCommand Create(
            byte version,
            IReadOnlyDictionary<ColorSwitchColorComponent, byte> values,
            DurationSet? duration)
{
            bool includeDuration = version >= 2 && duration.HasValue;
            Span<byte> commandParameters = stackalloc byte[1 + (2 * values.Count) + (includeDuration ? 1 : 0)];
            commandParameters[0] = (byte)(values.Count & 0b0001_1111);

            int idx = 1;
            foreach (KeyValuePair<ColorSwitchColorComponent, byte> pair in values)
            {
                commandParameters[idx++] = (byte)pair.Key;
                commandParameters[idx++] = pair.Value;
            }

            if (includeDuration)
            {
                commandParameters[idx] = duration!.Value.Value;
            }

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new ColorSwitchSetCommand(frame);
        }
    }

    private struct ColorSwitchStartLevelChangeCommand : ICommand
    {
        public ColorSwitchStartLevelChangeCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.StartLevelChange;

        public CommandClassFrame Frame { get; }

        public static ColorSwitchStartLevelChangeCommand Create(
            byte version,
            ColorSwitchChangeDirection direction,
            ColorSwitchColorComponent colorComponent,
            byte? startLevel,
            DurationSet? duration)
        {
            bool includeDuration = version >= 3 && duration.HasValue;
            Span<byte> commandParameters = stackalloc byte[3 + (includeDuration ? 1 : 0)];

            commandParameters[0] = (byte)((byte)direction << 6);
            if (!startLevel.HasValue)
            {
                // ignoreStartLevel bit
                commandParameters[0] |= 0b0010_0000;
            }

            commandParameters[1] = (byte)colorComponent;
            commandParameters[2] = startLevel.GetValueOrDefault();

            if (includeDuration)
            {
                commandParameters[3] = duration!.Value.Value;
            }

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new ColorSwitchStartLevelChangeCommand(frame);
        }
    }

    private struct ColorSwitchStopLevelChangeCommand : ICommand
    {
        public ColorSwitchStopLevelChangeCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ColorSwitch;

        public static byte CommandId => (byte)ColorSwitchCommand.StopLevelChange;

        public CommandClassFrame Frame { get; }

        public static ColorSwitchStartLevelChangeCommand Create(ColorSwitchColorComponent colorComponent)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = (byte)colorComponent;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new ColorSwitchStartLevelChangeCommand(frame);
        }
    }
}
