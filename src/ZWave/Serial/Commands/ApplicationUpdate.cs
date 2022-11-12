using ZWave.CommandClasses;
using static ZWave.Serial.Commands.CommandDataParsingHelpers;

namespace ZWave.Serial.Commands;

/// <summary>
/// Indicates which event has triggered the transmission of thie ApplicationControllerUpdate command.
/// </summary>
enum ApplicationUpdateEvent
{
    /// <summary>
    /// The SIS NodeID has been updated.
    /// </summary>
    SucId = 0x10,

    /// <summary>
    /// A node has been deleted from the network.
    /// </summary>
    DeleteDone = 0x20,

    /// <summary>
    /// A node has been deleted from the network.
    /// </summary>
    NewIdAssigned = 0x40,

    /// <summary>
    /// Another node in the network has requested the Z-Wave API Module to perform a neighbor discovery.
    /// </summary>
    RoutingPending = 0x80,

    /// <summary>
    /// The issued Request Node Information Command has not been acknowledged by the destination
    /// </summary>
    NodeInfoRequestFailed = 0x81,

    /// <summary>
    /// The issued Request Node Information Command has been acknowledged by the destination.
    /// </summary>
    NodeInfoRequestDone = 0x82,

    /// <summary>
    /// Another node sent a NOP Power Command to the Z-Wave API Module.
    /// The host application SHOULD NOT power down the Z-Wave API Module.
    /// </summary>
    NopPowerReceived = 0x83,

    /// <summary>
    /// A Node Information Frame has been received as unsolicited frame or in response to a Request Node Information Command
    /// </summary>
    NodeInfoReceived = 0x84,

    /// <summary>
    /// A SmartStart Prime Command has been received using the Z-Wave protocol.
    /// </summary>
    NodeInfoSmartStartHomeIdReceived = 0x85,

    /// <summary>
    /// A SmartStart Included Node Information Frame has been received (using either Z-Wave or Z-Wave Long Range protocol).
    /// </summary>
    IncludedNodeInfoReceived = 0x86,

    /// <summary>
    /// A SmartStart Prime Command has been received using the Z-Wave Long Range protocol.
    /// </summary>
    NodeInfoSmartStartHomeIdReceivedLongRange = 0x87,
}

internal struct ApplicationUpdateRequest : ICommand<ApplicationUpdateRequest>
{
    public ApplicationUpdateRequest(DataFrame frame)
    {
        Frame = frame;
    }

    public static DataFrameType Type => DataFrameType.REQ;

    public static CommandId CommandId => CommandId.ApplicationUpdate;

    public DataFrame Frame { get; }

    public ApplicationUpdateEvent Event => (ApplicationUpdateEvent)Frame.CommandParameters.Span[0];

    /// <summary>
    /// The generic data frame format used with most values of <see cref="Event"/>.
    /// </summary>
    /// <remarks>
    /// This only applies with specific values for <see cref="Event"/>. Using this with the wrong
    /// event type at best lead to garbled data and at worst lead to out of range exceptions.
    /// </remarks>
    public ApplicationUpdateGeneric Generic => new ApplicationUpdateGeneric(Frame.CommandParameters[1..]);

    /// <summary>
    /// The data frame format when the <see cref="Event"/> is <see cref="ApplicationUpdateEvent.NodeInfoSmartStartHomeIdReceived"/>
    /// or <see cref="ApplicationUpdateEvent.NodeInfoSmartStartHomeIdReceivedLongRange"/>
    /// </summary>
    /// <remarks>
    /// This only applies with specific values for <see cref="Event"/>. Using this with the wrong
    /// event type at best lead to garbled data and at worst lead to out of range exceptions.
    /// </remarks>
    public ApplicationUpdateSmartStartPrime? SmartStartPrime => Event == ApplicationUpdateEvent.NodeInfoSmartStartHomeIdReceived
        ? new ApplicationUpdateSmartStartPrime(Frame.CommandParameters[1..])
        : null;

    /// <summary>
    /// The data frame format when the <see cref="Event"/> is <see cref="ApplicationUpdateEvent.IncludedNodeInfoReceived"/>.
    /// </summary>
    /// <remarks>
    /// This only applies with specific values for <see cref="Event"/>. Using this with the wrong
    /// event type at best lead to garbled data and at worst lead to out of range exceptions.
    /// </remarks>
    public ApplicationUpdateSmartStartIncludedNodeInfo? SmartStartIncludedNodeInfo => Event == ApplicationUpdateEvent.IncludedNodeInfoReceived
        ? new ApplicationUpdateSmartStartIncludedNodeInfo(Frame.CommandParameters[1..])
        : null;

    public static ApplicationUpdateRequest Create(DataFrame frame) => new ApplicationUpdateRequest(frame);
}

internal struct ApplicationUpdateGeneric
{
    public ApplicationUpdateGeneric(ReadOnlyMemory<byte> data)
    {
        Data = data;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public byte NodeId => Data.Span[0];

    public byte BasicDeviceClass => Data.Span[2];

    public byte GenericDeviceClass => Data.Span[3];

    public byte SpecificDeviceClass => Data.Span[4];

    /// <summary>
    /// The list of non-secure implemented Command Classes by the remote node.
    /// </summary>
    public IReadOnlyList<CommandClassInfo> CommandClasses
    {
        get
        {
            ReadOnlySpan<byte> allCommandClasses = Data.Span[5..];
            return ParseCommandClasses(allCommandClasses);
        }
    }
}

internal struct ApplicationUpdateSmartStartPrime
{
    public ApplicationUpdateSmartStartPrime(ReadOnlyMemory<byte> data)
    {
        Data = data;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public byte NodeId => Data.Span[0];

    public ReceivedStatus ReceivedStatus => (ReceivedStatus)Data.Span[1];

    /// <summary>
    /// The NWI HomeID on which the SmartStart Prime Command was received.
    /// </summary>
    public uint HomeId => Data.Span[2..6].ToUInt32BE();

    public byte BasicDeviceClass => Data.Span[7];

    public byte GenericDeviceClass => Data.Span[8];

    public byte SpecificDeviceClass => Data.Span[9];

    /// <summary>
    /// The list of non-secure implemented Command Classes by the remote node.
    /// </summary>
    public IReadOnlyList<CommandClassInfo> CommandClasses
    {
        get
        {
            byte length = Data.Span[6];
            ReadOnlySpan<byte> allCommandClasses = Data.Span.Slice(10, length);
            return ParseCommandClasses(allCommandClasses);
        }
    }
}

internal struct ApplicationUpdateSmartStartIncludedNodeInfo
{
    public ApplicationUpdateSmartStartIncludedNodeInfo(ReadOnlyMemory<byte> data)
    {
        Data = data;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public byte NodeId => Data.Span[0];

    // Byte 1 is reserved

    public ReceivedStatus ReceivedStatus => (ReceivedStatus)Data.Span[2];

    /// <summary>
    /// The NWI HomeID for which the SmartStart Inclusion Node Information Frame was received
    /// </summary>
    public uint HomeId => Data.Span[3..7].ToUInt32BE();
}
