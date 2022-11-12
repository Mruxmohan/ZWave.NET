namespace ZWave.CommandClasses;

public enum ZWavePlusInfoCommand : byte
{
    /// <summary>
    /// Get additional information of the Z-Wave Plus device in question.
    /// </summary>
    Get = 0x01,

    /// <summary>
    /// Report version of Z-Wave Plus framework used and additional information of the Z-Wave Plus device in question.
    /// </summary>
    Report = 0x02,
}

public enum ZWavePlusRoleType : byte
{
    CentralStaticController = 0x00,
    SubStaticController = 0x01,
    PortableController = 0x02,
    ReportingPortableController = 0x03,
    PortableSlave = 0x04,
    AlwaysOnSlave = 0x05,
    ReportingSleepingSlave = 0x06,
    ListeningSleepingSlave = 0x07,
    NetworkAwareSlave = 0x08,
}

public readonly struct ZWavePlusInfo
{
    public ZWavePlusInfo(
        byte zwavePlusVersion,
        ZWavePlusRoleType roleType,
        ZWavePlusNodeType nodeType,
        ushort installerIconType,
        ushort userIconType)
    {
        ZWavePlusVersion = zwavePlusVersion;
        RoleType = roleType;
        NodeType = nodeType;
        InstallerIconType = installerIconType;
        UserIconType = userIconType;
    }

    /// <summary>
    /// Enables a future revision of the Z-Wave Plus framework where it is necessary to distinguish it from the previous frameworks
    /// </summary>
    public byte ZWavePlusVersion { get; }

    /// <summary>
    /// Indicates the role the Z-Wave Plus device in question possess in the network and functionalities supported.
    /// </summary>
    public ZWavePlusRoleType RoleType { get; }

    /// <summary>
    /// Indicates the type of node the Z-Wave Plus device in question possess in the network.
    /// </summary>
    public ZWavePlusNodeType NodeType { get; }

    /// <summary>
    /// Indicates the icon to use in Graphical User Interfaces for network management
    /// </summary>
    public ushort InstallerIconType { get; }

    /// <summary>
    /// Indicates the icon to use in Graphical User Interfaces for end users
    /// </summary>
    public ushort UserIconType { get; }
}

public enum ZWavePlusNodeType : byte
{
    /// <summary>
    /// Z-Wave Plus node
    /// </summary>
    Node = 0x00,

    /// <summary>
    /// Z-Wave Plus for IP gateway
    /// </summary>
    IpGateway = 0x02,
}

[CommandClass(CommandClassId.ZWavePlusInfo)]
public sealed class ZWavePlusInfoCommandClass : CommandClass<ZWavePlusInfoCommand>
{
    internal ZWavePlusInfoCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public ZWavePlusInfo? ZWavePlusInfo { get; private set; }

    public override bool? IsCommandSupported(ZWavePlusInfoCommand command)
        => command switch
        {
            ZWavePlusInfoCommand.Get => true,
            _ => false,
        };

    /// <summary>
    /// Get additional information of the Z-Wave Plus device in question.
    /// </summary>
    public async Task<object> GetAsync(CancellationToken cancellationToken)
    {
        var command = ZWavePlusInfoGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<ZWavePlusInfoReportCommand>(cancellationToken).ConfigureAwait(false);
        return ZWavePlusInfo!.Value;
    }

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        _ = await GetAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((ZWavePlusInfoCommand)frame.CommandId)
        {
            case ZWavePlusInfoCommand.Get:
            {
                // We don't expect to recieve these commands
                break;
            }
            case ZWavePlusInfoCommand.Report:
            {
                var command = new ZWavePlusInfoReportCommand(frame);
                ZWavePlusInfo = new ZWavePlusInfo(
                    command.ZWavePlusVersion,
                    command.RoleType,
                    command.NodeType,
                    command.InstallerIconType,
                    command.UserIconType);
                break;
            }
        }
    }

    private struct ZWavePlusInfoGetCommand : ICommand
    {
        public ZWavePlusInfoGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ZWavePlusInfo;

        public static byte CommandId => (byte)ZWavePlusInfoCommand.Get;

        public CommandClassFrame Frame { get; }

        public static ZWavePlusInfoGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new ZWavePlusInfoGetCommand(frame);
        }
    }

    private struct ZWavePlusInfoReportCommand : ICommand
    {
        public ZWavePlusInfoReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.ZWavePlusInfo;

        public static byte CommandId => (byte)ZWavePlusInfoCommand.Report;

        public CommandClassFrame Frame { get; }

        /// <summary>
        /// Enables a future revision of the Z-Wave Plus framework where it is necessary to distinguish it from the previous frameworks
        /// </summary>
        public byte ZWavePlusVersion => Frame.CommandParameters.Span[0];

        /// <summary>
        /// Indicates the role the Z-Wave Plus device in question possess in the network and functionalities supported.
        /// </summary>
        public ZWavePlusRoleType RoleType => (ZWavePlusRoleType)Frame.CommandParameters.Span[1];

        /// <summary>
        /// Indicates the type of node the Z-Wave Plus device in question possess in the network.
        /// </summary>
        public ZWavePlusNodeType NodeType => (ZWavePlusNodeType)Frame.CommandParameters.Span[2];

        /// <summary>
        /// Indicates the icon to use in Graphical User Interfaces for network management
        /// </summary>
        public ushort InstallerIconType => Frame.CommandParameters.Span[3..5].ToUInt16BE();

        /// <summary>
        /// Indicates the icon to use in Graphical User Interfaces for end users
        /// </summary>
        public ushort UserIconType => Frame.CommandParameters.Span[5..7].ToUInt16BE();
    }
}
