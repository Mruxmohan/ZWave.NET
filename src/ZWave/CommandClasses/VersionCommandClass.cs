﻿using ZWave.Serial;

namespace ZWave.CommandClasses;

public enum ZWaveLibraryType : byte
{
    NotApplicable = 0x00,

    StaticController = 0x01,

    Controller = 0x02,

    EnhancedSlave = 0x03,
    
    Slave = 0x04,
    
    Installer = 0x05,
    
    RoutingSlave = 0x06,
    
    BridgeController = 0x07,
    
    DeviceUnderTest = 0x08,

    NotApplicable2 = 0x09,

    AvRemote = 0x0a,

    AvDevice = 0x0b,
}

[CommandClass(CommandClassId.Version)]
public sealed class VersionCommandClass : CommandClass
{
    private readonly Dictionary<CommandClassId, byte> _commandClassVersions = new Dictionary<CommandClassId, byte>();

    public VersionCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
        foreach (KeyValuePair<CommandClassId, CommandClassInfo> pair in node.CommandClasses)
        {
            // Assume any implemented command class is at least version 1.
            // TODO: This should come from CommandClassInfo?
            _commandClassVersions.Add(pair.Key, 1);
        }
    }

    /// <summary>
    /// The Z-Wave Protocol Library Type
    /// </summary>
    public ZWaveLibraryType? LibraryType { get; private set; }

    /// <summary>
    /// Advertise information specific to Software Development Kits (SDK) provided by Silicon Labs
    /// </summary>
    public Version? ProtocolVersion { get; private set; }

    /// <summary>
    /// The firmware versions of the device.
    /// </summary>
    public IReadOnlyList<Version>? FirmwareVersions { get; private set; }

    /// <summary>
    /// A value which is unique to this particular version of the product
    /// </summary>
    public byte? HardwareVersion { get; private set; }

    /// <summary>
    /// The implemented command class version from a device. Until <see cref="GetCommandClassAsync(CommandClassId, CancellationToken)"/>
    /// is called for a given command class, the assumed version will be 1.
    /// </summary>
    public IReadOnlyDictionary<CommandClassId, byte> CommandClassVersions => _commandClassVersions;

    /// <summary>
    /// Whether the Z-Wave Software Get Command is supported.
    /// </summary>
    public bool ZWaveSoftwareSupported { get; private set; }

    /// <summary>
    /// The SDK version used for building the Z-Wave chip software components for the node.
    /// </summary>
    public Version? SdkVersion { get; private set; }

    /// <summary>
    /// The Z-Wave Application Framework API version used by the node
    /// </summary>
    public Version? ApplicationFrameworkApiVersion { get; private set; }

    /// <summary>
    /// The Z-Wave Application Framework build number running on the node.
    /// </summary>
    public ushort? ApplicationFramworkBuildNumber { get; private set; }

    /// <summary>
    /// The version of the Serial API exposed to a host CPU or a second Chip
    /// </summary>
    public Version? HostInterfaceVersion { get; private set; }

    /// <summary>
    /// The build number of the Serial API software exposed to a host CPU or second Chip.
    /// </summary>
    public ushort? HostInterfaceBuildNumber { get; private set; }

    /// <summary>
    /// The Z-Wave protocol version used by the node.
    /// </summary>
    public Version? ZWaveProtocolVersion { get; private set; }

    /// <summary>
    /// The actual build number of the Z-Wave protocol software used by the node.
    /// </summary>
    public ushort? ZWaveProtocolBuildNumber { get; private set; }

    /// <summary>
    /// The version of application software used by the node on its Z-Wave chip.
    /// </summary>
    public Version? ApplicationVersion { get; private set; }

    /// <summary>
    /// The actual build of the application software used by the node on its ZWave chip.
    /// </summary>
    public ushort? ApplicationBuildNumber { get; private set; }

    /// <summary>
    /// Request the library type, protocol version and application version from a device that supports
    /// the Version Command Class
    /// </summary>
    public async Task GetAsync(CancellationToken cancellationToken)
    {
        var command = VersionGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<VersionReportCommand>(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request the individual command class versions from a device.
    /// </summary>
    public async Task GetCommandClassAsync(CommandClassId commandClassId, CancellationToken cancellationToken)
    {
        var command = VersionCommandClassGetCommand.Create(commandClassId);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<VersionCommandClassReportCommand>(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request which version commands are supported by a node.
    /// </summary>
    public async Task GetCapabilitiesAsync(CancellationToken cancellationToken)
    {
        var command = VersionCapabilitiesGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<VersionCapabilitiesReportCommand>(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request the detailed Z-Wave chip software version information of a node
    /// </summary>
    public async Task GetZWaveSoftwareAsync(CancellationToken cancellationToken)
    {
        var command = VersionZWaveSoftwareGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<VersionZWaveSoftwareReportCommand>(cancellationToken).ConfigureAwait(false);
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((VersionCommand)frame.CommandId)
        {
            case VersionCommand.Get:
            case VersionCommand.CommandClassGet:
            case VersionCommand.CapabilitiesGet:
            case VersionCommand.ZWaveSoftwareGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case VersionCommand.Report:
            {
                var command = new VersionReportCommand(frame);
                LibraryType = command.ZWaveLibraryType;
                ProtocolVersion = command.ZWaveProtocolVersion;
                FirmwareVersions = command.FirmwareVersions;
                HardwareVersion = command.HardwareVersion;
                break;
            }
            case VersionCommand.CommandClassReport:
            {
                var command = new VersionCommandClassReportCommand(frame);
                var commandClassId = command.RequestedCommandClass;
                var commandClassVersion = command.CommandClassVersion;
                _commandClassVersions[commandClassId] = commandClassVersion;

                // TODO: Update the Node
                break;
            }
            case VersionCommand.CapabilitiesReport:
            {
                var command = new VersionCapabilitiesReportCommand(frame);
                ZWaveSoftwareSupported = command.ZWaveSoftwareSupported;
                break;
            }
            case VersionCommand.ZWaveSoftwareReport:
            {
                var command = new VersionZWaveSoftwareReportCommand(frame);
                SdkVersion = command.SdkVersion;
                ApplicationFrameworkApiVersion = command.ApplicationFrameworkApiVersion;
                ApplicationFramworkBuildNumber = command.ApplicationFramworkBuildNumber;
                HostInterfaceVersion = command.HostInterfaceVersion;
                HostInterfaceBuildNumber = command.HostInterfaceBuildNumber;
                ZWaveProtocolVersion = command.ZWaveProtocolVersion;
                ZWaveProtocolBuildNumber = command.ZWaveProtocolBuildNumber;
                ApplicationVersion = command.ApplicationVersion;
                ApplicationBuildNumber = command.ApplicationBuildNumber;
                break;
            }
        }
    }

    private enum VersionCommand : byte
    {
        /// <summary>
        /// Request the library type, protocol version and application version from a device that supports
        /// the Version Command Class
        /// </summary>
        Get = 0x11,

        /// <summary>
        /// Advertise the library type, protocol version and application version from a device.
        /// </summary>
        Report = 0x12,

        /// <summary>
        /// Request the individual command class versions from a device.
        /// </summary>
        CommandClassGet = 0x13,

        /// <summary>
        /// Report the individual command class versions from a device.
        /// </summary>
        CommandClassReport = 0x14,

        /// <summary>
        /// Request which version commands are supported by a node.
        /// </summary>
        CapabilitiesGet = 0x15,

        /// <summary>
        /// Advertise the version commands supported by the sending node
        /// </summary>
        CapabilitiesReport = 0x16,

        /// <summary>
        /// Request the detailed Z-Wave chip software version information of a node
        /// </summary>
        ZWaveSoftwareGet = 0x17,

        /// <summary>
        /// Advertise the detailed Z-Wave chip software version information of a node.
        /// </summary>
        ZWaveSoftwareReport = 0x18,
    }

    private struct VersionGetCommand : ICommand<VersionGetCommand>
    {
        public VersionGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.Get;

        public CommandClassFrame Frame { get; }

        public static VersionGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new VersionGetCommand(frame);
        }
    }

    private struct VersionReportCommand : ICommand<VersionReportCommand>
    {
        public VersionReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The Z-Wave Protocol Library Type
        /// </summary>
        public ZWaveLibraryType ZWaveLibraryType => (ZWaveLibraryType)Frame.CommandParameters.Span[0];

        /// <summary>
        /// Advertise information specific to Software Development Kits (SDK) provided by Silicon Labs
        /// </summary>
        public Version ZWaveProtocolVersion => new Version(Frame.CommandParameters.Span[1], Frame.CommandParameters.Span[2]);

        /// <summary>
        /// The firmware versions of the device.
        /// </summary>
        public IReadOnlyList<Version> FirmwareVersions
        {
            get
            {
                int numFirmwareVersions = 1;
                if (Frame.CommandParameters.Length > 6)
                {
                    numFirmwareVersions += Frame.CommandParameters.Span[6];
                }

                var firmwareVersions = new Version[numFirmwareVersions];
                firmwareVersions[0] = new Version(Frame.CommandParameters.Span[3], Frame.CommandParameters.Span[4]);

                for (int i = 1; i < numFirmwareVersions; i++)
                {
                    // THe starting offset should be 7, but account for i starting at 1
                    var versionOffset = 5 + (2 * i);
                    firmwareVersions[i] = new Version(
                        Frame.CommandParameters.Span[versionOffset],
                        Frame.CommandParameters.Span[versionOffset + 1]);
                }

                return firmwareVersions;
            }
        }

        /// <summary>
        /// A value which is unique to this particular version of the product
        /// </summary>
        public byte? HardwareVersion
            => Frame.CommandParameters.Length > 5
                ? Frame.CommandParameters.Span[5]
                : null;
    }

    private struct VersionCommandClassGetCommand : ICommand<VersionGetCommand>
    {
        public VersionCommandClassGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.CommandClassGet;

        public CommandClassFrame Frame { get; }

        public static VersionGetCommand Create(CommandClassId commandClassId)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = (byte)commandClassId;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new VersionGetCommand(frame);
        }
    }

    private struct VersionCommandClassReportCommand : ICommand<VersionCommandClassReportCommand>
    {
        public VersionCommandClassReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.CommandClassReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// What Command Class the returned version belongs to.
        /// </summary>
        public CommandClassId RequestedCommandClass => (CommandClassId)Frame.CommandParameters.Span[0];

        /// <summary>
        /// The Command Class Version.
        /// </summary>
        public byte CommandClassVersion => Frame.CommandParameters.Span[1];
    }

    private struct VersionCapabilitiesGetCommand : ICommand<VersionCapabilitiesGetCommand>
    {
        public VersionCapabilitiesGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.CapabilitiesGet;

        public CommandClassFrame Frame { get; }

        public static VersionCapabilitiesGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new VersionCapabilitiesGetCommand(frame);
        }
    }

    private struct VersionCapabilitiesReportCommand : ICommand<VersionCapabilitiesReportCommand>
    {
        public VersionCapabilitiesReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.CapabilitiesReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// Advertise support for the version information queried with the Version Get Command
        /// </summary>
        /// <remarks>
        /// This field must be set to 1, so it's not really useful...
        /// </remarks>
        public bool VersionSupported => (Frame.CommandParameters.Span[0] & 0b0000_0001) != 0;

        /// <summary>
        /// Advertise support for the Command Class version information queried with the Version Command Class Get Command
        /// </summary>
        /// <remarks>
        /// This field must be set to 1, so it's not really useful...
        /// </remarks>
        public bool CommandClassSupported => (Frame.CommandParameters.Span[0] & 0b0000_0010) != 0;

        /// <summary>
        /// Advertise support for the detailed Z-Wave software version information queried with the Version Z-Wave Software
        /// Get Command.
        /// </summary>
        public bool ZWaveSoftwareSupported => (Frame.CommandParameters.Span[0] & 0b0000_0100) != 0;
    }

    private struct VersionZWaveSoftwareGetCommand : ICommand<VersionZWaveSoftwareGetCommand>
    {
        public VersionZWaveSoftwareGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.ZWaveSoftwareGet;

        public CommandClassFrame Frame { get; }

        public static VersionZWaveSoftwareGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new VersionZWaveSoftwareGetCommand(frame);
        }
    }

    private struct VersionZWaveSoftwareReportCommand : ICommand<VersionZWaveSoftwareReportCommand>
    {
        public VersionZWaveSoftwareReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Version;

        public static byte CommandId => (byte)VersionCommand.ZWaveSoftwareReport;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// The SDK version used for building the Z-Wave chip software components for the node.
        /// </summary>
        public Version? SdkVersion => ParseVersion(Frame.CommandParameters.Span[0..3]);

        /// <summary>
        /// The Z-Wave Application Framework API version used by the node
        /// </summary>
        public Version? ApplicationFrameworkApiVersion => ParseVersion(Frame.CommandParameters.Span[3..6]);

        /// <summary>
        /// The Z-Wave Application Framework build number running on the node.
        /// </summary>
        public ushort? ApplicationFramworkBuildNumber => ParseBuildNumber(Frame.CommandParameters.Span[6..8]);

        /// <summary>
        /// The version of the Serial API exposed to a host CPU or a second Chip
        /// </summary>
        public Version? HostInterfaceVersion => ParseVersion(Frame.CommandParameters.Span[8..11]);

        /// <summary>
        /// The build number of the Serial API software exposed to a host CPU or second Chip.
        /// </summary>
        public ushort? HostInterfaceBuildNumber => ParseBuildNumber(Frame.CommandParameters.Span[11..13]);

        /// <summary>
        /// The Z-Wave protocol version used by the node.
        /// </summary>
        public Version? ZWaveProtocolVersion => ParseVersion(Frame.CommandParameters.Span[13..16]);

        /// <summary>
        /// The actual build number of the Z-Wave protocol software used by the node.
        /// </summary>
        public ushort? ZWaveProtocolBuildNumber => ParseBuildNumber(Frame.CommandParameters.Span[16..18]);

        /// <summary>
        /// The version of application software used by the node on its Z-Wave chip.
        /// </summary>
        public Version? ApplicationVersion => ParseVersion(Frame.CommandParameters.Span[18..21]);

        /// <summary>
        /// The actual build of the application software used by the node on its ZWave chip.
        /// </summary>
        public ushort? ApplicationBuildNumber => ParseBuildNumber(Frame.CommandParameters.Span[21..23]);

        private static Version? ParseVersion(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 3)
            {
                throw new ArgumentException("Expected exacly 3 bytes", nameof(bytes));
            }

            var major = bytes[0];
            var minor = bytes[1];
            var patch = bytes[2];

            // The value 0 MUST indicate that this field is unused.
            return major == 0 && minor == 0 && patch == 0
                ? null
                : new Version(major, minor, patch);
        }

        private static ushort? ParseBuildNumber(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != 2)
            {
                throw new ArgumentException("Expected exacly 2 bytes", nameof(bytes));
            }

            ushort buildNum = bytes.ToUInt16BE();

            // The value 0 MUST indicate that this field is unused
            return buildNum != 0
                ? buildNum
                : null;
        }
    }
}
