namespace ZWave.CommandClasses;

public enum NotificationType : byte
{
    SmokeAlarm = 0x01,
    COAlarm = 0x02,
    CO2Alarm = 0x03,
    HeatAlarm = 0x04,
    WaterAlarm = 0x05,
    AccessControl = 0x06,
    HomeSecurity = 0x07,
    PowerManagement = 0x08,
    System = 0x09,
    EmergencyAlarm = 0x0a,
    Clock = 0x0b,
    Appliance = 0x0c,
    HomeHealth = 0x0d,
    Siren = 0x0e,
    WaterValve = 0x0f,
    WeatherAlarm = 0x10,
    Irrigation = 0x11,
    GasAlarm = 0x12,
    PestControl = 0x13,
    LightSensor = 0x14,
    WaterQualityMonitoring = 0x15,
    HomeMonitoring = 0x16,
    RequestPendingNotification = 0xff,
}

public enum NotificationCommand : byte
{
    /// <summary>
    /// Request the supported Notifications for a specified Notification Type.
    /// </summary>
    EventSupportedGet = 0x01,

    /// <summary>
    /// Advertise supported events/states for a specified Notification Type
    /// </summary>
    EventSupportedReport = 0x02,

    /// <summary>
    /// Request if the unsolicited transmission of a specific Notification Type is enabled
    /// </summary>
    Get = 0x04,

    /// <summary>
    /// Advertises an event or state Notification
    /// </summary>
    Report = 0x05,

    /// <summary>
    /// Enable or disable the unsolicited transmission of a specific Notification Type
    /// </summary>
    Set = 0x06,

    /// <summary>
    /// Request the supported notification types.
    /// </summary>
    SupportedGet = 0x07,

    /// <summary>
    /// Advertise the supported notification types in the application.
    /// </summary>
    SupportedReport = 0x08,
}

public readonly struct Notification
{
    public Notification(
        byte? v1AlarmType,
        byte? v1AlarmLevel,
        byte? zensorNetSourceNodeId,
        bool? notificationStatus,
        byte? notificationType,
        byte? notificationEvent,
        ReadOnlyMemory<byte>? eventParameters,
        byte? sequenceNumber)
    {
        V1AlarmType = v1AlarmType;
        V1AlarmLevel = v1AlarmLevel;
        ZensorNetSourceNodeId = zensorNetSourceNodeId;
        NotificationStatus = notificationStatus;
        NotificationType = notificationType;
        NotificationEvent = notificationEvent;
        EventParameters = eventParameters;
        SequenceNumber = sequenceNumber;
    }

    public byte? V1AlarmType { get; }

    public byte? V1AlarmLevel { get; }

    /// <summary>
    /// Zensor Net Source Node ID, which detected the alarm condition.
    /// </summary>
    public byte? ZensorNetSourceNodeId { get; }

    public bool? NotificationStatus { get; }

    public byte? NotificationType { get; }

    public byte? NotificationEvent { get; }

    public ReadOnlyMemory<byte>? EventParameters { get; }

    public byte? SequenceNumber { get; }
}

public readonly struct SupportedNotifications
{
    public SupportedNotifications(
        bool supportsV1Alarm,
        IReadOnlySet<NotificationType> supportedNotificationTypes)
    {
        SupportsV1Alarm = supportsV1Alarm;
        SupportedNotificationTypes = supportedNotificationTypes;
    }

    public bool SupportsV1Alarm { get; }

    public IReadOnlySet<NotificationType> SupportedNotificationTypes { get; }
}

public readonly struct SupportedNotificationEvents
{
    public SupportedNotificationEvents(
        NotificationType notificationType,
        IReadOnlySet<byte> supportedNotificationEvents)
    {
        NotificationType = notificationType;
        SupportedEvents = supportedNotificationEvents;
    }

    public NotificationType NotificationType { get; }

    public IReadOnlySet<byte> SupportedEvents { get; }
}

// Note: Version < 3 is the Alarm Command Class
[CommandClass(CommandClassId.Notification)]
public sealed class NotificationCommandClass : CommandClass<NotificationCommand>
{
    private Dictionary<NotificationType, SupportedNotificationEvents?>? _supportedNotificationEvents;

    internal NotificationCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    // TODO: Should be an event. Although shouldn't all state changes?
    public Notification? LastNotification { get; private set; }

    public SupportedNotifications? SupportedNotifications { get; private set; }

    public IReadOnlyDictionary<NotificationType, SupportedNotificationEvents?>? SupportedNotificationEvents => _supportedNotificationEvents;

    /// <inheritdoc />
    public override bool? IsCommandSupported(NotificationCommand command)
        => command switch
        {
            NotificationCommand.Get => true,
            NotificationCommand.Set => Version.HasValue ? Version >= 2 : null,
            NotificationCommand.SupportedGet => Version.HasValue ? Version >= 2 : null,
            NotificationCommand.EventSupportedGet => Version.HasValue ? Version >= 3 : null,
            _ => false,
        };

    internal override async Task InterviewAsync(CancellationToken cancellationToken)
    {
        if (IsCommandSupported(NotificationCommand.SupportedGet).GetValueOrDefault(false))
        {
            SupportedNotifications supportedNotifications = await GetSupportedAsync(cancellationToken).ConfigureAwait(false);

            if (IsCommandSupported(NotificationCommand.EventSupportedGet).GetValueOrDefault(false))
            {
                foreach (NotificationType notificationType in supportedNotifications.SupportedNotificationTypes)
                {
                    _ = await GetEventSupportedAsync(notificationType, cancellationToken);

                    // TODO: Determine whether this is the push or pull mode. Foe this we need to implement the AGI CC and
                    //       Some other semi-complicated logic. For now, assume push.

                    // Enable reports
                    await SetAsync(notificationType, true, cancellationToken).ConfigureAwait(false);
                }
            }
        }
    }

    public async Task<Notification> GetV1Async(byte alarmType, CancellationToken cancellationToken)
    {
        var command = NotificationGetV1Command.Create(alarmType);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<NotificationReportCommand>(cancellationToken).ConfigureAwait(false);
        return LastNotification!.Value;
    }

    public async Task<Notification> GetAsync(NotificationType notificationType, byte? notificationEvent, CancellationToken cancellationToken)
    {
        var command = NotificationGetCommand.Create(EffectiveVersion, notificationType, notificationEvent);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<NotificationReportCommand>(cancellationToken).ConfigureAwait(false);
        return LastNotification!.Value;
    }

    public async Task SetAsync(NotificationType notificationType, bool notificationStatus, CancellationToken cancellationToken)
    {
        var command = NotificationSetCommand.Create(notificationType, notificationStatus);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        // No report is expected from this command.
    }

    public async Task<SupportedNotifications> GetSupportedAsync(CancellationToken cancellationToken)
    {
        var command = NotificationSupportedGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<NotificationSupportedReportCommand>(cancellationToken).ConfigureAwait(false);
        return SupportedNotifications!.Value;
    }

    public async Task<SupportedNotificationEvents> GetEventSupportedAsync(NotificationType notificationType, CancellationToken cancellationToken)
    {
        var command = NotificationEventSupportedGetCommand.Create(notificationType);
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<NotificationEventSupportedReportCommand>(cancellationToken).ConfigureAwait(false);
        return _supportedNotificationEvents![notificationType]!.Value;
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((NotificationCommand)frame.CommandId)
        {
            case NotificationCommand.Get:
            case NotificationCommand.Set:
            case NotificationCommand.SupportedGet:
            case NotificationCommand.EventSupportedGet:
            {
                // We don't expect to recieve these commands
                break;
            }
            case NotificationCommand.Report:
            {
                var command = new NotificationReportCommand(frame, Version);
                LastNotification = new Notification(
                    command.V1AlarmType,
                    command.V1AlarmLevel,
                    command.ZensorNetSourceNodeId,
                    command.NotificationStatus,
                    command.NotificationType,
                    command.NotificationEvent,
                    command.EventParameters,
                    command.SequenceNumber);
                break;
            }
            case NotificationCommand.SupportedReport:
            {
                var command = new NotificationSupportedReportCommand(frame);
                IReadOnlySet<NotificationType> supportedNotificationTypes = command.SupportedNotificationTypes;
                SupportedNotifications = new SupportedNotifications(
                    command.SupportsV1Alarm,
                    supportedNotificationTypes);

                var newSupportedNotificationEvents = new Dictionary<NotificationType, SupportedNotificationEvents?>(supportedNotificationTypes.Count);
                foreach (NotificationType notificationType in supportedNotificationTypes)
                {
                    // Persist any existing known state.
                    if (SupportedNotificationEvents == null
                        || !SupportedNotificationEvents.TryGetValue(notificationType, out SupportedNotificationEvents? supportedNotificationEvents))
                    {
                        supportedNotificationEvents = null;
                    }

                    newSupportedNotificationEvents.Add(notificationType, supportedNotificationEvents);
                }

                _supportedNotificationEvents = newSupportedNotificationEvents;
                break;
            }
            case NotificationCommand.EventSupportedReport:
            {
                var command = new NotificationEventSupportedReportCommand(frame);
                _supportedNotificationEvents![command.NotificationType] = new SupportedNotificationEvents(
                    command.NotificationType,
                    command.SupportedNotificationEvents);
                break;
            }
        }
    }

    private struct NotificationGetV1Command : ICommand
    {
        public NotificationGetV1Command(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.Get;

        public CommandClassFrame Frame { get; }

        public static NotificationGetV1Command Create(byte alarmType)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = alarmType;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new NotificationGetV1Command(frame);
        }
    }

    private struct NotificationGetCommand : ICommand
    {
        public NotificationGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.Get;

        public CommandClassFrame Frame { get; }

        public static NotificationGetCommand Create(
            byte version,
            NotificationType notificationType,
            byte? notificationEvent)
        {
            bool includeNotificationEvent = version >= 3;
            Span<byte> commandParameters = stackalloc byte[2 + (includeNotificationEvent ? 1 : 0)];
            commandParameters[0] = 0;
            commandParameters[1] = (byte)notificationType;
            if (includeNotificationEvent)
            {
                commandParameters[2] = notificationType == NotificationType.RequestPendingNotification
                    ? (byte)0x00
                    : notificationEvent.GetValueOrDefault(0);
            }

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new NotificationGetCommand(frame);
        }
    }

    private struct NotificationReportCommand : ICommand
    {
        // Note: Notifications describe point-in-time events, so avoid version checking if we don't have the version
        // since we don't want to lose any events before the version is determined.
        private readonly byte? _version;

        public NotificationReportCommand(CommandClassFrame frame, byte? version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.Report;

        public CommandClassFrame Frame { get; }

        public byte? V1AlarmType
        {
            get
            {
                if (!ShouldUseV1Values)
                {
                    return null;
                }

                var value = Frame.CommandParameters.Span[0];
                return value == 0 ? null : value;
            }
        }

        public byte? V1AlarmLevel
        {
            get
            {
                if (!ShouldUseV1Values)
                {
                    return null;
                }

                var value = Frame.CommandParameters.Span[1];
                return value == 0 ? null : value;
            }
        }

        private bool ShouldUseV1Values
        {
            get
            {
                byte? notificationEvent = NotificationEvent;
                return !notificationEvent.HasValue || notificationEvent.Value == 0xfe;
            }
        }

        /// <summary>
        /// Zensor Net Source Node ID, which detected the alarm condition.
        /// </summary>
        // Discontinued as of V4
        public byte? ZensorNetSourceNodeId => (_version == 2 || _version == 3) && Frame.CommandParameters.Length > 2
            ? Frame.CommandParameters.Span[2]
            : null;

        public bool? NotificationStatus => (!_version.HasValue || _version >= 2) && Frame.CommandParameters.Length > 3
            ? Frame.CommandParameters.Span[3] switch
            {
                0x00 => false,
                0xff => true,
                _ => null,
            }
            : null;

        public byte? NotificationType => (!_version.HasValue || _version >= 2) && Frame.CommandParameters.Length > 4
            ? Frame.CommandParameters.Span[4]
            : null;

        public byte? NotificationEvent => (!_version.HasValue || _version >= 2) && Frame.CommandParameters.Length > 5
            ? Frame.CommandParameters.Span[5]
            : null;

        private int NumEventParameters => (!_version.HasValue || _version >= 2) && Frame.CommandParameters.Length > 6
            ? Frame.CommandParameters.Span[6] & 0b0001_1111
            : 0;

        // TODO: Parse this. According to docs:
        //       Parameters for each Event/State Notification are defined in [18]. 
        //       This field MAY carry an encapsulated command.In this case, the field MUST include the complete
        //       command structure, i.e.Command Class, Command and all mandatory command field
        public ReadOnlyMemory<byte>? EventParameters => (!_version.HasValue || _version >= 2) && Frame.CommandParameters.Length > 7
            ? Frame.CommandParameters.Slice(7, NumEventParameters)
            : null;

        public byte? SequenceNumber
        {
            get
            {
                if (_version.HasValue && _version < 3)
                {
                    return null;
                }

                if (Frame.CommandParameters.Length < 7)
                {
                    return null;
                }

                var hasSequenceNumber = (Frame.CommandParameters.Span[6] & 0b1000_0000) != 0;
                if (!hasSequenceNumber)
                {
                    return null;
                }

                return Frame.CommandParameters.Span[7 + NumEventParameters];
            }
        }
    }

    private struct NotificationSetCommand : ICommand
    {
        public NotificationSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.Set;

        public CommandClassFrame Frame { get; }

        public static NotificationSetCommand Create(NotificationType notificationType, bool notificationStatus)
        {
            Span<byte> commandParameters = stackalloc byte[2];
            commandParameters[0] = (byte)notificationType;
            commandParameters[1] = notificationStatus ? (byte)0xff : (byte)0x00;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new NotificationSetCommand(frame);
        }
    }

    private struct NotificationSupportedGetCommand : ICommand
    {
        public NotificationSupportedGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.SupportedGet;

        public CommandClassFrame Frame { get; }

        public static NotificationSupportedGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new NotificationSupportedGetCommand(frame);
        }
    }

    private struct NotificationSupportedReportCommand : ICommand
    {
        public NotificationSupportedReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.SupportedReport;

        public CommandClassFrame Frame { get; }

        public bool SupportsV1Alarm => (Frame.CommandParameters.Span[0] & 0b1000_0000) != 0;

        public IReadOnlySet<NotificationType> SupportedNotificationTypes
        {
            get
            {
                var supportedNotificationTypes = new HashSet<NotificationType>();

                int numBitMasks = (Frame.CommandParameters.Span[0] & 0b0001_1111);
                ReadOnlySpan<byte> bitMask = Frame.CommandParameters.Span.Slice(1, numBitMasks);
                for (int byteNum = 0; byteNum < bitMask.Length; byteNum++)
                {
                    for (int bitNum = 0; bitNum < 8; bitNum++)
                    {
                        if ((bitMask[byteNum] & (1 << bitNum)) != 0)
                        {
                            NotificationType notificationType = (NotificationType)((byteNum << 3) + bitNum);
                            supportedNotificationTypes.Add(notificationType);
                        }
                    }
                }

                return supportedNotificationTypes;
            }
        }
    }

    private struct NotificationEventSupportedGetCommand : ICommand
    {
        public NotificationEventSupportedGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.EventSupportedGet;

        public CommandClassFrame Frame { get; }

        public static NotificationEventSupportedGetCommand Create(NotificationType notificationType)
        {
            Span<byte> commandParameters = stackalloc byte[1];
            commandParameters[0] = (byte)notificationType;

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new NotificationEventSupportedGetCommand(frame);
        }
    }

    private struct NotificationEventSupportedReportCommand : ICommand
    {
        public NotificationEventSupportedReportCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.Notification;

        public static byte CommandId => (byte)NotificationCommand.EventSupportedReport;

        public CommandClassFrame Frame { get; }

        public NotificationType NotificationType => (NotificationType)Frame.CommandParameters.Span[0];

        public IReadOnlySet<byte> SupportedNotificationEvents
        {
            get
            {
                var supportedNotificationEvents = new HashSet<byte>();

                int numBitMasks = (Frame.CommandParameters.Span[1] & 0b0001_1111);
                ReadOnlySpan<byte> bitMask = Frame.CommandParameters.Span.Slice(2, numBitMasks);
                for (int byteNum = 0; byteNum < bitMask.Length; byteNum++)
                {
                    for (int bitNum = 0; bitNum < 8; bitNum++)
                    {
                        if ((bitMask[byteNum] & (1 << bitNum)) != 0)
                        {
                            byte notificationEvent = (byte)((byteNum << 3) + bitNum);
                            supportedNotificationEvents.Add(notificationEvent);
                        }
                    }
                }

                return supportedNotificationEvents;
            }
        }
    }
}
