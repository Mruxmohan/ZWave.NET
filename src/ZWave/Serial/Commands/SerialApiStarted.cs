namespace ZWave.Serial.Commands;

/// <summary>
/// Describes the reason the Z-Wave API Module has been woken up.
/// </summary>
internal enum SerialApiStartedWakeUpReason : byte
{
    /// <summary>
    /// Reset or external interrupt
    /// </summary>
    Reset = 0x00,

    /// <summary>
    /// Timer.
    /// </summary>
    WakeUpTimer = 0x01,

    /// <summary>
    /// Wake Up Beam.
    /// </summary>
    WakeUpBeam = 0x02,

    /// <summary>
    /// Reset triggered by the watchdog.
    /// </summary>
    WatchdogReset = 0x03,

    /// <summary>
    /// External interrupt.
    /// </summary>
    ExternalInterrupt = 0x04,

    /// <summary>
    /// External interrupt.
    /// </summary>
    PowerUp = 0x05,

    /// <summary>
    /// USB Suspend.
    /// </summary>
    UsbSuspend = 0x06,

    /// <summary>
    /// Reset triggered by software.
    /// </summary>
    SoftwareReset = 0x07,

    /// <summary>
    /// Emergency watchdog reset.
    /// </summary>
    EmergencyWatchdogReset = 0x08,

    /// <summary>
    /// Brownout circuit.
    /// </summary>
    BrownoutCircuit = 0x09,

    /// <summary>
    /// Unknown reason.
    /// </summary>
    Unknown = 0xff,
}

[Flags]
internal enum SerialApiStartedSupportedProtocols : byte
{
    /// <summary>
    /// Indicates if the Z-Wave API module supports Z-Wave
    /// </summary>
    ZWaveLongRange = 0x01,
}

/// <summary>
/// This command is used by the Z-Wave Module to indicate that it is ready to be operated after a reboot or reset operation
/// </summary>
internal struct SerialApiStartedRequest : ICommand<SerialApiStartedRequest>
{
    public SerialApiStartedRequest(DataFrame frame)
    {
        Frame = frame;
    }

    public static DataFrameType Type => DataFrameType.REQ;

    public static CommandId CommandId => CommandId.SerialApiStarted;

    public DataFrame Frame { get; }

    /// <summary>
    /// Gets the event that caused the Z-Wave API module to start
    /// </summary>
    public SerialApiStartedWakeUpReason WakeUpReason => (SerialApiStartedWakeUpReason)Frame.CommandParameters.Span[0];

    /// <summary>
    /// Gets whether the Watchdog is enabled.
    /// </summary>
    public bool WatchdogStarted => Frame.CommandParameters.Span[1] == 0x01;

    /// <summary>
    /// Gets the currently configured listening capabilities configured for the Z-Wave API Module.
    /// </summary>
    public byte DeviceOptionMask => Frame.CommandParameters.Span[2];

    /// <summary>
    /// Gets the currently configured Generic Device Type.
    /// </summary>
    public byte GenericDeviceType => Frame.CommandParameters.Span[3];

    /// <summary>
    /// Gets the currently configured Generic Device Type.
    /// </summary>
    public byte SpecificDeviceType => Frame.CommandParameters.Span[4];

    private byte CommandClassesLength => Frame.CommandParameters.Span[5];

    /// <summary>
    /// Gets the list of supported Command Classes advertised by the Z-Wave API Module upon request.
    /// </summary>
    public ReadOnlyMemory<byte> CommandClasses => Frame.CommandParameters.Slice(6, CommandClassesLength);

    /// <summary>
    /// Gets additional supported protocols by the Z-Wave API module.
    /// </summary>
    public SerialApiStartedSupportedProtocols SupportedProtocols
        => Frame.CommandParameters.Length >= 7 + CommandClassesLength
            ? (SerialApiStartedSupportedProtocols)Frame.CommandParameters.Span[6 + CommandClassesLength]
            : 0x00;

    public static SerialApiStartedRequest Create(DataFrame frame) => new SerialApiStartedRequest(frame);
}
