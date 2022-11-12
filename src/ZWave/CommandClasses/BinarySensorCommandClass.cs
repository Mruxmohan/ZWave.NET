namespace ZWave.CommandClasses;

public enum BinarySensorType : byte
{
    GeneralPurpose = 0x01,
    Smoke = 0x02,
    CO = 0x03,
    CO2 = 0x04,
    Heat = 0x05,
    Water = 0x06,
    Freeze = 0x07,
    Tamper = 0x08,
    Aux = 0x09,
    DoorWindow = 0x0a,
    Tilt = 0x0b,
    Motion = 0x0c,
    GlassBreak = 0x0d,
    FirstSupported = 0xff,
}

public enum BinarySensorCommand : byte
{
    /// <summary>
    /// Request the status of the specific sensor device.
    /// </summary>
    Get = 0x02,

    /// <summary>
    /// Advertise a sensor value.
    /// </summary>
    Report = 0x03,

    /// <summary>
    /// Request the supported sensor types from the binary sensor device.
    /// </summary>
    SupportedGet = 0x01,

    /// <summary>
    /// Indicates the supported sensor types of the binary sensor device.
    /// </summary>
    SupportedReport = 0x04,
}

[CommandClass(CommandClassId.BinarySensor)]
public sealed class BinarySensorCommandClass : CommandClass<BinarySensorCommand>
{
    private Dictionary<BinarySensorType, bool?>? _sensorValues;

    public BinarySensorCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    /// <summary>
    /// The supported sensor types by the binary sensor device.
    /// </summary>
    public IReadOnlySet<BinarySensorType>? SupportedSensorTypes { get; private set; }

    /// <summary>
    /// The values of each supported sensor type.
    /// </summary>
    public IReadOnlyDictionary<BinarySensorType, bool?>? SensorValues => _sensorValues;

    public override bool? IsCommandSupported(BinarySensorCommand command)
        => command switch
        {
            BinarySensorCommand.Get => true,
            BinarySensorCommand.SupportedGet => Version.HasValue ? Version >= 2 : null,
            _ => false,
        };

    public async Task<bool> GetAsync(
        BinarySensorType? sensorType,
        CancellationToken cancellationToken)
    {
        var command = BinarySensorGetCommand.Create(EffectiveVersion, sensorType);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);

        var reportFrame = await AwaitNextReportAsync<BinarySensorReportCommand>(
            predicate: frame =>
            {
                // Ensure the sensor type matches. If one wasn't provided, we don't know the default sensor type, so just
                // return the next report. We can't know for sure whether this is the reply to this command as we don't
                // know the device's default sensor type, but this overload is really just here for back-compat and the
                // caller should really always provide a sensor type.
                var command = new BinarySensorReportCommand(frame, EffectiveVersion);
                return !sensorType.HasValue
                    || sensorType.Value == BinarySensorType.FirstSupported
                    || command.SensorType == sensorType.Value;
            },
            cancellationToken).ConfigureAwait(false);
        var reportCommand = new BinarySensorReportCommand(reportFrame, EffectiveVersion);
        return reportCommand.SensorValue;
    }

    public async Task<IReadOnlySet<BinarySensorType>> GetSupportedSensorTypesAsync(CancellationToken cancellationToken)
    {
        var command = BinarySensorSupportedGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<BinarySensorSupportedReportCommand>(cancellationToken).ConfigureAwait(false);
        return SupportedSensorTypes!;
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        if (IsCommandSupported(BinarySensorCommand.SupportedGet).GetValueOrDefault())
        {
            IReadOnlySet<BinarySensorType> supportedSensorTypes = await GetSupportedSensorTypesAsync(cancellationToken).ConfigureAwait(false);
            foreach (BinarySensorType sensorType in supportedSensorTypes)
            {
                _ = await GetAsync(sensorType, cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            _ = await GetAsync(sensorType: null, cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((BinarySensorCommand)frame.CommandId)
        {
            case BinarySensorCommand.Get:
            case BinarySensorCommand.SupportedGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case BinarySensorCommand.Report:
            {
                var command = new BinarySensorReportCommand(frame, EffectiveVersion);
                var sensorType = command.SensorType.GetValueOrDefault(BinarySensorType.FirstSupported);
                _sensorValues![sensorType] = command.SensorValue;
                break;
            }
            case BinarySensorCommand.SupportedReport:
            {
                var command = new BinarySensorSupportedReportCommand(frame);
                SupportedSensorTypes = command.SupportedSensorTypes;

                var newSensorValues = new Dictionary<BinarySensorType, bool?>();
                foreach (BinarySensorType sensorType in SupportedSensorTypes)
                {
                    // Persist any existing known state.
                    if (SensorValues == null
                        || !SensorValues.TryGetValue(sensorType, out bool? sensorValue))
                    {
                        sensorValue = null;
                    }

                    newSensorValues.Add(sensorType, sensorValue);
                }

                _sensorValues = newSensorValues;

                break;
            }
        }
    }

    private struct BinarySensorGetCommand : ICommand
    {
        public BinarySensorGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySensor;

        public static byte CommandId => (byte)BinarySensorCommand.Get;

        public CommandClassFrame Frame { get; }

        public static BinarySensorGetCommand Create(byte version, BinarySensorType? sensorType)
        {
            if (version >= 2 && sensorType.HasValue)
            {
                Span<byte> commandParameters = stackalloc byte[1];
                commandParameters[0] = (byte)sensorType.Value;

                CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
                return new BinarySensorGetCommand(frame);
            }
            else
            {
                CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
                return new BinarySensorGetCommand(frame);
            }
        }
    }

    private struct BinarySensorReportCommand : ICommand
    {
        private readonly byte _version;

        public BinarySensorReportCommand(CommandClassFrame frame, byte version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySensor;

        public static byte CommandId => (byte)BinarySensorCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The sensor value
        /// </summary>
        public bool SensorValue => Frame.CommandParameters.Span[0] == 0xff;

        /// <summary>
        /// The sensor type
        /// </summary>
        public BinarySensorType? SensorType => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (BinarySensorType)Frame.CommandParameters.Span[1]
            : null;
    }

    private struct BinarySensorSupportedGetCommand : ICommand
    {
        public BinarySensorSupportedGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySensor;

        public static byte CommandId => (byte)BinarySensorCommand.SupportedGet;

        public CommandClassFrame Frame { get; }

        public static BinarySensorSupportedGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new BinarySensorSupportedGetCommand(frame);
        }
    }

    private struct BinarySensorSupportedReportCommand : ICommand
    {
        public BinarySensorSupportedReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.BinarySensor;

        public static byte CommandId => (byte)BinarySensorCommand.SupportedReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The supported sensor types by the binary sensor device.
        /// </summary>
        public IReadOnlySet<BinarySensorType> SupportedSensorTypes
        {
            get
            {
                var supportedSensorTypes = new HashSet<BinarySensorType>();

                ReadOnlySpan<byte> bitMask = Frame.CommandParameters.Span[1..];
                for (int byteNum = 0; byteNum < bitMask.Length; byteNum++)
                {
                    for (int bitNum = 0; bitNum < 8; bitNum++)
                    {
                        if ((bitMask[byteNum] & (1 << bitNum)) != 0)
                        {
                            BinarySensorType sensorType = (BinarySensorType)((byteNum << 3) + bitNum);
                            supportedSensorTypes.Add(sensorType);
                        }
                    }
                }

                return supportedSensorTypes;
            }
        }
    }
}
