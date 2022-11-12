namespace ZWave.CommandClasses;

public struct BatteryLevel
{
    public BatteryLevel(byte value)
    {
        Value = value;
    }

    public byte Value { get; }

    public int Level => Value == 0xff ? 0 : Value;

    public bool IsLow => Value == 0xff;

    public static implicit operator BatteryLevel(byte b) => new BatteryLevel(b);
}

public enum BatteryChargingStatus : byte
{
    Discharging = 0x00,

    Charging = 0x01,

    Maintaining = 0x02,
}

public enum BatterRechargeOrReplaceStatus : byte
{
    /// <summary>
    /// The battery does not need to be recharged or replaced.
    /// </summary>
    Ok = 0x00,

    /// <summary>
    /// The battery must be recharged or replaced soon.
    /// </summary>
    Soon = 0x01,

    // Value 2 is undefined. From the spec: "If bit 1 is set to 1, bit 0 MUST also be set to 1."

    /// <summary>
    /// The battery must be recharged or replaced now.
    /// </summary>
    Now = 0x03,
}

public enum BatteryTemperatureScale : byte
{
    Celcius = 0x00,
}

public enum BatteryCommand : byte
{
    /// <summary>
    /// Request the level of a battery.
    /// </summary>
    Get = 0x02,

    /// <summary>
    /// Report the battery level of a battery operated device
    /// </summary>
    Report = 0x03,

    /// <summary>
    /// Query the health of the battery, particularly the battery temperature and maximum capacity.
    /// </summary>
    HealthGet = 0x04,

    /// <summary>
    /// Report the maximum capacity of the battery as well as the temperature of the battery.
    /// </summary>
    HealthReport = 0x05,
}

public readonly struct BatteryState
{
    public BatteryState(
        BatteryLevel batteryLevel,
        BatteryChargingStatus? chargingStatus,
        bool? isRechargeable,
        bool? isBackupBattery,
        bool? isOverheating,
        bool? hasLowFluid,
        BatterRechargeOrReplaceStatus? replaceRechargeStatus,
        bool? isLowTemperature,
        bool? disconnected)
    {
        BatteryLevel = batteryLevel;
        ChargingStatus = chargingStatus;
        IsRechargeable = isRechargeable;
        IsBackupBattery = isBackupBattery;
        IsOverheating = isOverheating;
        HasLowFluid = hasLowFluid;
        ReplaceRechargeStatus = replaceRechargeStatus;
        IsLowTemperature = isLowTemperature;
        Disconnected = disconnected;
    }

    /// <summary>
    /// The percentage indicating the battery level
    /// </summary>
    public BatteryLevel BatteryLevel { get; }

    /// <summary>
    /// The charging status of a battery.
    /// </summary>
    public BatteryChargingStatus? ChargingStatus { get; }

    /// <summary>
    /// Indicates if the battery is rechargeable or not
    /// </summary>
    public bool? IsRechargeable { get; }

    /// <summary>
    /// Illustrate if the battery is utilized for back-up purposes of a mains powered connected device.
    /// </summary>
    public bool? IsBackupBattery { get; }

    /// <summary>
    /// Indicate if overheating is detected at the battery.
    /// </summary>
    public bool? IsOverheating { get; }

    /// <summary>
    /// Indicate if the battery fluid is low and should be refilled
    /// </summary>
    public bool? HasLowFluid { get; }

    /// <summary>
    /// Indicate if the battery needs to be recharged or replaced.
    /// </summary>
    public BatterRechargeOrReplaceStatus? ReplaceRechargeStatus { get; }

    /// <summary>
    /// Advertise if the battery of a device has stopped charging due to low temperature
    /// </summary>
    public bool? IsLowTemperature { get; }

    /// <summary>
    /// Indicate if the battery is currently disconnected or removed from the node.
    /// </summary>
    public bool? Disconnected { get; }
}

public readonly struct BatteryHealth
{
    public BatteryHealth(byte? maximumCapacity, BatteryTemperatureScale batteryTemperatureScale, double? batteryTemperature)
    {
        MaximumCapacity = maximumCapacity;
        BatteryTemperatureScale = batteryTemperatureScale;
        BatteryTemperature = batteryTemperature;
    }

    /// <summary>
    /// Report the percentage indicating the maximum capacity of the battery
    /// </summary>
    public byte? MaximumCapacity { get; }

    /// <summary>
    /// The scale used for the battery temperature value
    /// </summary>
    public BatteryTemperatureScale BatteryTemperatureScale { get; }

    /// <summary>
    /// The temperature of the battery
    /// </summary>
    public double? BatteryTemperature { get; }
}

[CommandClass(CommandClassId.Battery)]
public sealed class BatteryCommandClass : CommandClass<BatteryCommand>
{
    public BatteryCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public BatteryState? State { get; private set; }

    public BatteryHealth? Health { get; private set; }

    public override bool? IsCommandSupported(BatteryCommand command)
        => command switch
        {
            BatteryCommand.Get => true,
            BatteryCommand.HealthGet => Version.HasValue ? Version >= 2 : null,
            _ => false,
        };

    public async Task<BatteryState> GetAsync(CancellationToken cancellationToken)
    {
        var command = BatteryGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<BatteryReportCommand>(cancellationToken).ConfigureAwait(false);
        return State!.Value;
    }

    public async Task<BatteryHealth> GetHealthAsync(CancellationToken cancellationToken)
    {
        var command = BatteryHealthGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<BatteryHealthReportCommand>(cancellationToken).ConfigureAwait(false);
        return Health!.Value;
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        _ = await GetAsync(cancellationToken).ConfigureAwait(false);

        if (IsCommandSupported(BatteryCommand.HealthGet).GetValueOrDefault())
        {
            _ = await GetHealthAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((BatteryCommand)frame.CommandId)
        {
            case BatteryCommand.Get:
            case BatteryCommand.HealthGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case BatteryCommand.Report:
            {
                var command = new BatteryReportCommand(frame, EffectiveVersion);
                State = new BatteryState(
                    command.BatteryLevel,
                    command.ChargingStatus,
                    command.IsRechargeable,
                    command.IsBackupBattery,
                    command.IsOverheating,
                    command.HasLowFluid,
                    command.ReplaceRechargeStatus,
                    command.IsLowTemperature,
                    command.Disconnected);
                break;
            }
            case BatteryCommand.HealthReport:
            {
                var command = new BatteryHealthReportCommand(frame);
                Health = new BatteryHealth(
                    command.MaximumCapacity,
                    command.BatteryTemperatureScale,
                    command.BatteryTemperature);
                break;
            }
        }
    }

    private struct BatteryGetCommand : ICommand
    {
        public BatteryGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Battery;

        public static byte CommandId => (byte)BatteryCommand.Get;

        public CommandClassFrame Frame { get; }

        public static BatteryGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new BatteryGetCommand(frame);
        }
    }

    private struct BatteryReportCommand : ICommand
    {
        private readonly byte _version;

        public BatteryReportCommand(CommandClassFrame frame, byte version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.Battery;

        public static byte CommandId => (byte)BatteryCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The percentage indicating the battery level
        /// </summary>
        public BatteryLevel BatteryLevel => Frame.CommandParameters.Span[0];

        /// <summary>
        /// The charging status of a battery.
        /// </summary>
        public BatteryChargingStatus? ChargingStatus => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (BatteryChargingStatus)((Frame.CommandParameters.Span[1] & 0b1100_0000) >> 6)
            : null;

        /// <summary>
        /// Indicates if the battery is rechargeable or not
        /// </summary>
        public bool? IsRechargeable => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (Frame.CommandParameters.Span[1] & 0b0010_0000) != 0
            : null;

        /// <summary>
        /// Illustrate if the battery is utilized for back-up purposes of a mains powered connected device.
        /// </summary>
        public bool? IsBackupBattery => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (Frame.CommandParameters.Span[1] & 0b0001_0000) != 0
            : null;

        /// <summary>
        /// Indicate if overheating is detected at the battery.
        /// </summary>
        public bool? IsOverheating => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (Frame.CommandParameters.Span[1] & 0b0000_1000) != 0
            : null;

        /// <summary>
        /// Indicate if the battery fluid is low and should be refilled
        /// </summary>
        public bool? HasLowFluid => _version >= 2 && Frame.CommandParameters.Length > 1
            ? (Frame.CommandParameters.Span[1] & 0b0000_0100) != 0
            : null;

        /// <summary>
        /// Indicate if the battery needs to be recharged or replaced.
        /// </summary>
        public BatterRechargeOrReplaceStatus? ReplaceRechargeStatus => _version >= 2 && Frame.CommandParameters.Length > 1
            // This is spec'd as a bitmask but it's basically just an enum
            ? (BatterRechargeOrReplaceStatus)(Frame.CommandParameters.Span[1] & 0b0000_0011)
            : null;

        /// <summary>
        /// Advertise if the battery of a device has stopped charging due to low temperature
        /// </summary>
        public bool? IsLowTemperature => _version >= 3 && Frame.CommandParameters.Length > 2
            ? (Frame.CommandParameters.Span[2] & 0b0000_0010) != 0
            : null;

        /// <summary>
        /// Indicate if the battery is currently disconnected or removed from the node.
        /// </summary>
        public bool? Disconnected => _version >= 2 && Frame.CommandParameters.Length > 2
            ? (Frame.CommandParameters.Span[2] & 0b0000_0001) != 0
            : null;
    }

    private struct BatteryHealthGetCommand : ICommand
    {
        public BatteryHealthGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Battery;

        public static byte CommandId => (byte)BatteryCommand.HealthGet;

        public CommandClassFrame Frame { get; }

        public static BatteryGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new BatteryGetCommand(frame);
        }
    }

    private struct BatteryHealthReportCommand : ICommand
    {
        public BatteryHealthReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Battery;

        public static byte CommandId => (byte)BatteryCommand.HealthReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// Report the percentage indicating the maximum capacity of the battery
        /// </summary>
        public byte? MaximumCapacity
        {
            get
            {
                // 0xff means unknown.
                byte value = Frame.CommandParameters.Span[0];
                return value == 0xff ? null : value;
            }
        }

        /// <summary>
        /// The scale used for the battery temperature value
        /// </summary>
        public BatteryTemperatureScale BatteryTemperatureScale
            => (BatteryTemperatureScale)((Frame.CommandParameters.Span[1] & 0b0001_1000) >> 3);

        /// <summary>
        /// The temperature of the battery
        /// </summary>
        public double? BatteryTemperature
        {
            get
            {
                int precision = (Frame.CommandParameters.Span[1] & 0b1110_0000) >> 5;

                int valueSize = Frame.CommandParameters.Span[1] & 0b0000_0111;
                if (valueSize == 0)
                {
                    // THe battery temperature is unknown
                    return null;
                }

                var valueBytes = Frame.CommandParameters.Span.Slice(2, valueSize);

                if (valueBytes.Length > sizeof(int))
                {
                    throw new InvalidOperationException($"The value's size was more than {sizeof(int)} bytes, and currently we can't handle that");
                }

                int rawValue = valueBytes.ToInt32BE();

                return rawValue / Math.Pow(10, precision);
            }
        }
    }
}
