namespace ZWave.CommandClasses;

public enum CommandClassId : byte
{
    NoOperation = 0x00,

    /// <summary>
    /// The Basic Command Class allows a controlling device to operate the primary functionality of a supporting
    /// device without any further knowledge.
    /// </summary>
    Basic = 0x20,

    ControllerReplication = 0x21,
    ApplicationStatus = 0x22,
    ZIp = 0x23,

    /// <summary>
    /// The Binary Switch Command Class is used to control the On/Off state of supporting nodes.
    /// </summary>
    BinarySwitch = 0x25,

    /// <summary>
    /// The Multilevel Switch Command Class is used to control devices with multilevel capability.
    /// </summary>
    MultilevelSwitch = 0x26,

    AllSwitch = 0x27,
    BinaryToggleSwitch = 0x28,
    MultilevelToggleSwitch = 0x29,
    SceneActivation = 0x2B,
    SceneActuatorConfiguration = 0x2c,
    SceneControllerConfiguration = 0x2d,

    /// <summary>
    /// The Binary Sensor Command Class is used to realize binary sensors, such as movement sensors and door/window sensors.
    /// </summary>
    BinarySensor = 0x30,

    /// <summary>
    /// The Multilevel Sensor Command Class is used to advertise numerical sensor readings.
    /// </summary>
    MultilevelSensor = 0x31,

    Meter = 0x32,

    /// <summary>
    /// The Color Switch Command Class is used to control color capable devices. 
    /// </summary>
    ColorSwitch = 0x33,

    NetworkManagementInclusion = 0x34,
    PulseMeter = 0x35,
    BasicTariffInformation = 0x36,
    HrvStatus = 0x37,
    HrvControl = 0x39,
    DemandControlPlanConfiguration = 0x3a,
    DemandControlPlanMonitor = 0x3b,
    MeterTableConfiguration = 0x3c,
    MeterTableMonitor = 0x3d,
    MeterTablePushConfiguration = 0x3e,
    Prepayment = 0x3f,
    ThermostatMode = 0x40,
    PrepaymentEncapsulation = 0x41,
    ThermostatOperatingState = 0x42,
    ThermostatSetpoint = 0x43,
    ThermostatFanMode = 0x44,
    ThermostatFanState = 0x45,
    ClimateControlSchedule = 0x46,
    ThermostatSetback = 0x47,
    RateTableConfiguration = 0x48,
    RateTableMonitor = 0x49,
    TariffTableConfiguration = 0x4a,
    TariffTableMonitor = 0x4b,
    DoorLockLogging = 0x4c,
    NetworkManagementBasicNode = 0x4d,
    ScheduleEntryLock = 0x4e,
    ZIp6LoWpan = 0x4f,
    BasicWindowCovering = 0x50,
    MoveToPositionWindowCovering = 0x51,
    NetworkManagementProxy = 0x52,
    Schedule = 0x53,
    NetworkManagementPrimary = 0x54,
    TransportService = 0x55,
    Crc16Encapsulation = 0x56,
    ApplicationCapability = 0x57,
    ZIpND = 0x58,
    AssociationGroupInformation = 0x59,
    DeviceResetLocally = 0x5a,
    CentralScene = 0x5b,
    IpAssociation = 0x5c,
    AntiTheft = 0x5d,
    ZWavePlusInfo = 0x5e,
    ZIpGateway = 0x5f,
    MultiChannel = 0x60,
    ZIpPortal = 0x61,
    DoorLock = 0x62,
    UserCode = 0x63,
    HumidityControlSetpoint = 0x64,
    BarrierOperator = 0x66,
    NetworkManagementInstallationAndMaintenance = 0x67,
    ZIpNamingAndLocation = 0x68,
    Mailbox = 0x69,
    WindowCovering = 0x6a,
    Irrigation = 0x6b,
    Supervision = 0x6c,
    HumidityControlMode = 0x6d,
    HumidityControlOperatingState = 0x6e,
    EntryControl = 0x6f,
    Configuration = 0x70,

    /// <summary>
    /// The Notification Command Class is used to advertise events or states, such as movement detection, door open/close
    /// or system failure
    /// </summary>
    Notification = 0x71,

    /// <summary>
    /// The Manufacturer Specific Command Class is used to advertise manufacturer specific and device specific information.
    /// </summary>
    ManufacturerSpecific = 0x72,

    /// <summary>
    /// The Powerlevel Command Class defines RF transmit power controlling Commands useful when installing or testing a network.
    /// </summary>
    Powerlevel = 0x73,

    InclusionController = 0x74,
    Protection = 0x75,
    Lock = 0x76,
    NodeNamingAndLocation = 0x77,
    NodeProvisioning = 0x78,
    SoundSwitch = 0x79,
    FirmwareUpdateMetaData = 0x7a,
    GroupingName = 0x7b,
    RemoteAssociationActivation = 0x7c,
    RemoteAssociationConfiguration = 0x7d,
    AntiTheftUnlock = 0x7e,

    /// <summary>
    /// The Battery Command Class is used to request and report the battery types, status and levels of a given device.
    /// </summary>
    Battery = 0x80,

    Clock = 0x81,
    Hail = 0x82,

    /// <summary>
    /// The Wake Up Command Class allows a battery-powered device to notify another device (always listening), that it is awake
    /// and ready to receive any queued commands.
    /// </summary>
    WakeUp = 0x84,

    Association = 0x85,

    /// <summary>
    /// The Version Command Class may be used to obtain the Z-Wave library type, the Z-Wave protocol version used by the
    /// application, the individual command class versions used by the application and the vendor specific application version
    /// from a Z-Wave enabled device.
    /// </summary>
    Version = 0x86,
    
    Indicator = 0x87,
    Proprietary = 0x88,
    Language = 0x89,
    Time = 0x8a,
    TimeParameters = 0x8b,
    GeographicLocation = 0x8c,
    MultiChannelAssociation = 0x8e,
    MultiCommand = 0x8f,
    EnergyProduction = 0x90,
    ManufacturerProprietary = 0x91,
    ScreenMetaData = 0x92,
    ScreenAttributes = 0x93,
    SimpleAvControl = 0x94,
    Security0 = 0x98,
    IpConfiguration = 0x9a,
    AssociationCommandConfiguration = 0x9b,
    AlarmSensor = 0x9c,
    AlarmSilence = 0x9d,
    SensorConfiguration = 0x9e,
    Security2 = 0x9f,
    IrRepeater = 0xa0,
    Authentication = 0xa1,
    AuthenticationMediaWrite = 0xa2,
    GenericSchedule = 0xa3,
    SupportControlMark = 0xef,
}
