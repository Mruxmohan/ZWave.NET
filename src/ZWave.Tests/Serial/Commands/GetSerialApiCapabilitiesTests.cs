using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetSerialApiCapabilitiesTests : CommandTestBase
{
    private record GetSerialApiCapabilitiesResponseData(
        byte SerialApiVersion,
        byte SerialApiRevision,
        ushort ManufacturerId,
        ushort ManufacturerProductType,
        ushort ManufacturerProductId,
        HashSet<CommandId> SupportedCommandIds);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetSerialApiCapabilities,
            new[]
            {
                (Request: GetSerialApiCapabilitiesRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetSerialApiCapabilitiesResponse, GetSerialApiCapabilitiesResponseData>(
            DataFrameType.RES,
            CommandId.GetSerialApiCapabilities,
            new[]
            {
                (
                    CommandParameters: new byte[]
                    {
                        0x01, 0x02, 0x00, 0x86, 0x00, 0x01, 0x00, 0x5a,
                        0xfe, 0x87, 0x7f, 0x88, 0xcf, 0x7f, 0xc0, 0x4f,
                        0xfb, 0xdf, 0xfd, 0xe0, 0x67, 0x00, 0x80, 0x80,
                        0x00, 0x80, 0x86, 0x00, 0x01, 0x00, 0xe8, 0x73,
                        0x00, 0x80, 0x0f, 0x00, 0x00, 0x60, 0x00, 0x00
                    },
                    ExpectedData: new GetSerialApiCapabilitiesResponseData(
                        SerialApiVersion: 1,
                        SerialApiRevision: 2,
                        ManufacturerId: 134,
                        ManufacturerProductType: 1,
                        ManufacturerProductId: 90,
                        SupportedCommandIds: new HashSet<CommandId>
                        {
                            CommandId.GetInitData,
                            CommandId.ApplicationNodeInformation,
                            CommandId.ApplicationCommandHandler,
                            CommandId.GetControllerCapabilities,
                            CommandId.SerialApiSetTimeouts,
                            CommandId.GetSerialApiCapabilities,
                            CommandId.SoftReset,
                            CommandId.SendDataMultiEx,
                            CommandId.SerialApiStarted,
                            CommandId.SerialApiSetup,
                            CommandId.SetRFReceiveMode,
                            CommandId.SetSleepMode,
                            CommandId.SendNodeInformation,
                            CommandId.SendData,
                            CommandId.SendDataMulti,
                            CommandId.GetLibraryVersion,
                            CommandId.SendDataAbort,
                            CommandId.RFPowerLevelSet,
                            CommandId.GetRandomWord,
                            CommandId.MemoryGetId,
                            CommandId.MemoryGetByte,
                            CommandId.MemoryPutByte,
                            CommandId.MemoryGetBuffer,
                            CommandId.MemoryPutBuffer,
                            CommandId.FlashAutoProgSet,
                            CommandId.NvrGetValue,
                            CommandId.NvmGetId,
                            CommandId.NvmExtReadLongBuffer,
                            CommandId.NvmExtWriteLongBuffer,
                            CommandId.NvmExtReadLongByte,
                            CommandId.NvmExtWriteLongByte,
                            (CommandId)46,
                            (CommandId)47,
                            CommandId.ClearTxTimers,
                            CommandId.GetTxTimer,
                            CommandId.ClearNetworkStats,
                            CommandId.GetNetworkStats,
                            CommandId.GetBackgroundRSSI,
                            CommandId.SetListenBeforeTalkThreshold,
                            CommandId.RemoveNodeIdFromNetwork,
                            CommandId.GetNodeProtocolInfo,
                            CommandId.SetDefault,
                            CommandId.ReplicationReceiveComplete,
                            CommandId.ReplicationSend,
                            CommandId.AssignReturnRoute,
                            CommandId.DeleteReturnRoute,
                            CommandId.RequestNodeNeighborUpdate,
                            CommandId.ApplicationUpdate,
                            CommandId.AddNodeToNetwork,
                            CommandId.RemoveNodeFromNetwork,
                            CommandId.CreateNewPrimaryController,
                            CommandId.ControllerChange,
                            CommandId.AssignPriorityReturnRoute,
                            CommandId.SetLearnMode,
                            CommandId.AssignSucReturnRoute,
                            CommandId.RequestNetworkUpdate,
                            CommandId.SetSucNodeId,
                            CommandId.DeleteSucReturnRoute,
                            CommandId.GetSucNodeId,
                            CommandId.SendSucId,
                            CommandId.AssignPrioritySucReturnRoute,
                            CommandId.ExploreRequestInclusion,
                            CommandId.ExploreRequestExclusion,
                            CommandId.RequestNodeInfo,
                            CommandId.RemoveFailedNode,
                            CommandId.IsFailedNode,
                            CommandId.ReplaceFailedNode,
                            (CommandId)102,
                            (CommandId)103,
                            CommandId.FirmwareUpdate,
                            CommandId.GetRoutingInfo,
                            CommandId.LockRoute,
                            CommandId.GetPriorityRoute,
                            CommandId.SetPriorityRoute,
                            (CommandId)152,
                            (CommandId)161,
                            CommandId.SetWutTimeout,
                            CommandId.WatchdogEnable,
                            CommandId.WatchdogDisable,
                            CommandId.WatchdogKick,
                            CommandId.SetExtIntLevel,
                            CommandId.RFPowerLevelGet,
                            CommandId.TypeLibrary,
                            CommandId.SendTestFrame,
                            CommandId.GetProtocolStatus,
                            CommandId.SetPromiscuousMode,
                            (CommandId)209,
                            (CommandId)210,
                            (CommandId)211,
                            CommandId.SetRoutingMax,
                            (CommandId)238,
                            (CommandId)239,
                        })
                )
            });
}
