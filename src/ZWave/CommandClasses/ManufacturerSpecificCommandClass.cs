using System.Text;

namespace ZWave.CommandClasses;

public enum ManufacturerSpecificDeviceIdType : byte
{
    FactoryDefault = 0x00,

    SerialNumber = 0x01,

    PseudoRandom = 0x02,
}

public enum ManufacturerSpecificCommand : byte
{
    /// <summary>
    /// Request manufacturer specific information from another node.
    /// </summary>
    Get = 0x04,

    /// <summary>
    /// Advertise manufacturer specific device information.
    /// </summary>
    Report = 0x05,

    /// <summary>
    /// Request device specific information.
    /// </summary>
    DeviceSpecificGet = 0x06,

    /// <summary>
    /// Advertise device specific information.
    /// </summary>
    DeviceSpecificReport = 0x07,
}

public readonly struct ManufacturerInformation
{
    public ManufacturerInformation(ushort manufacturerId, ushort productTypeId, ushort productId)
    {
        ManufacturerId = manufacturerId;
        ProductTypeId = productTypeId;
        ProductId = productId;
    }

    /// <summary>
    /// The unique ID identifying the manufacturer of the device.
    /// </summary>
    public ushort ManufacturerId { get; }

    /// <summary>
    /// A unique ID identifying the actual product type.
    /// </summary>
    public ushort ProductTypeId { get; }

    /// <summary>
    /// A unique ID identifying the actual product.
    /// </summary>
    public ushort ProductId { get; }
}

[CommandClass(CommandClassId.ManufacturerSpecific)]
public sealed class ManufacturerSpecificCommandClass : CommandClass<ManufacturerSpecificCommand>
{
    private readonly Dictionary<ManufacturerSpecificDeviceIdType, string> _deviceIds = new();

    public ManufacturerSpecificCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public ManufacturerInformation? ManufacturerInformation { get; private set; }

    public IReadOnlyDictionary<ManufacturerSpecificDeviceIdType, string> DeviceIds => _deviceIds;

    public override bool? IsCommandSupported(ManufacturerSpecificCommand command)
        => command switch
        {
            ManufacturerSpecificCommand.Get => true,
            ManufacturerSpecificCommand.DeviceSpecificGet => Version.HasValue ? Version >= 2 : null,
            _ => false,
        };

    public async Task<ManufacturerInformation> GetAsync(CancellationToken cancellationToken)
    {
        var command = ManufacturerSpecificGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<ManufacturerSpecificReportCommand>(cancellationToken).ConfigureAwait(false);
        return ManufacturerInformation!.Value;
    }

    public async Task<string> GetDeviceIdAsync(ManufacturerSpecificDeviceIdType deviceIdType, CancellationToken cancellationToken)
    {
        var command = ManufacturerSpecificDeviceSpecificGetCommand.Create(deviceIdType);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);

        // From the spec:
        //      In case the Device ID Type specified in a Device Specific Get command is not supported by the 
        //      responding node, the responding node MAY return the factory default Device ID Type (as if receiving 
        //      the value 0 in the Device Specific Get command).
        // So we can't check the device id type from the report with the one provided, nor can we use the provided device id type as a key to lookup in _deviceIds.
        var reportFrame = await AwaitNextReportAsync<ManufacturerSpecificDeviceSpecificReportCommand>(cancellationToken).ConfigureAwait(false);
        var reportCommand = new ManufacturerSpecificDeviceSpecificReportCommand(reportFrame);
        return reportCommand.DeviceId;
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        _ = await GetAsync(cancellationToken).ConfigureAwait(false);

        // TODO: Does this CC need to be interviewed before Version CC (zwavejs does this)?
        //       If so, we can't really make this call.
        if (IsCommandSupported(ManufacturerSpecificCommand.DeviceSpecificGet).GetValueOrDefault())
        {
            // Spec: A sending node SHOULD specify a value of zero when issuing the Device Specific Get command since the responding node may only be able to return one Device ID Type.
            _ = await GetDeviceIdAsync(ManufacturerSpecificDeviceIdType.FactoryDefault, cancellationToken).ConfigureAwait(false);
        }
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((ManufacturerSpecificCommand)frame.CommandId)
        {
            case ManufacturerSpecificCommand.Get:
            case ManufacturerSpecificCommand.DeviceSpecificGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case ManufacturerSpecificCommand.Report:
            {
                var command = new ManufacturerSpecificReportCommand(frame);
                ManufacturerInformation = new ManufacturerInformation(
                    command.ManufacturerId,
                    command.ProductTypeId,
                    command.ProductId);
                break;
            }
            case ManufacturerSpecificCommand.DeviceSpecificReport:
            {
                var command = new ManufacturerSpecificDeviceSpecificReportCommand(frame);
                _deviceIds[command.DeviceIdType] = command.DeviceId;
                break;
            }
        }
    }

    private struct ManufacturerSpecificGetCommand : ICommand
    {
        public ManufacturerSpecificGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ManufacturerSpecific;

        public static byte CommandId => (byte)ManufacturerSpecificCommand.Get;

        public CommandClassFrame Frame { get; }

        public static ManufacturerSpecificGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new ManufacturerSpecificGetCommand(frame);
        }
    }

    private struct ManufacturerSpecificReportCommand : ICommand
    {
        public ManufacturerSpecificReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ManufacturerSpecific;

        public static byte CommandId => (byte)ManufacturerSpecificCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The unique ID identifying the manufacturer of the device.
        /// </summary>
        public ushort ManufacturerId => Frame.CommandParameters.Span[0..2].ToUInt16BE();

        /// <summary>
        /// A unique ID identifying the actual product type.
        /// </summary>
        public ushort ProductTypeId => Frame.CommandParameters.Span[2..4].ToUInt16BE();

        /// <summary>
        /// A unique ID identifying the actual product.
        /// </summary>
        public ushort ProductId => Frame.CommandParameters.Span[4..6].ToUInt16BE();
    }

    private struct ManufacturerSpecificDeviceSpecificGetCommand : ICommand
    {
        public ManufacturerSpecificDeviceSpecificGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ManufacturerSpecific;

        public static byte CommandId => (byte)ManufacturerSpecificCommand.DeviceSpecificGet;

        public CommandClassFrame Frame { get; }

        public static ManufacturerSpecificDeviceSpecificGetCommand Create(ManufacturerSpecificDeviceIdType deviceIdType)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = (byte)deviceIdType;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new ManufacturerSpecificDeviceSpecificGetCommand(frame);
        }
    }

    private struct ManufacturerSpecificDeviceSpecificReportCommand : ICommand
    {
        public ManufacturerSpecificDeviceSpecificReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ManufacturerSpecific;

        public static byte CommandId => (byte)ManufacturerSpecificCommand.DeviceSpecificReport;

        public CommandClassFrame Frame { get; }

        public ManufacturerSpecificDeviceIdType DeviceIdType => (ManufacturerSpecificDeviceIdType)(Frame.CommandParameters.Span[0] & 0b0000_0111);

        public string DeviceId
        {
            get
            {
                int deviceIdDataLength = Frame.CommandParameters.Span[1] & 0b0001_1111;
                ReadOnlySpan<byte> deviceIdData = Frame.CommandParameters.Span.Slice(2, deviceIdDataLength);

                int deviceIdDataFormat = (Frame.CommandParameters.Span[1] & 0b1110_0000) >> 5;
                if (deviceIdDataFormat == 0)
                {
                    // UTF-8
                    return Encoding.UTF8.GetString(deviceIdData);
                }
                else
                {
                    // Binary
                    return $"0x{Convert.ToHexString(deviceIdData)}";
                }
            }
        }
    }
}
