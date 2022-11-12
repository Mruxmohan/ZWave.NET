using ZWave.CommandClasses;
using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class ApplicationUpdateTests : CommandTestBase
{
    private record ApplicationUpdateGenericData(
        byte NodeId,
        byte BasicDeviceClass,
        byte GenericDeviceClass,
        byte SpecificDeviceClass,
        IReadOnlyList<CommandClassInfo> CommandClasses);

    private record ApplicationUpdateSmartStartPrimeData(
        byte NodeId,
        ReceivedStatus ReceivedStatus,
        uint HomeId,
        byte BasicDeviceClass,
        byte GenericDeviceClass,
        byte SpecificDeviceClass,
        IReadOnlyList<CommandClassInfo> CommandClasses);

    private record ApplicationUpdateSmartStartIncludedNodeInfoData(
        byte NodeId,
        ReceivedStatus ReceivedStatus,
        uint HomeId);

    private record ApplicationUpdateRequestData(
        ApplicationUpdateEvent Event,
        ApplicationUpdateGenericData Generic,
        ApplicationUpdateSmartStartPrimeData? SmartStartPrime,
        ApplicationUpdateSmartStartIncludedNodeInfoData? SmartStartIncludedNodeInfo);

    [TestMethod]
    public void Request()
        => TestReceivableCommand<ApplicationUpdateRequest, ApplicationUpdateRequestData>(
            DataFrameType.REQ,
            CommandId.ApplicationUpdate,
            new[]
            {
                (
                    CommandParameters: new byte[]
                    {
                        0x84, 0x02, 0x11, 0x04, 0x11, 0x01, 0x5e, 0x56,
                        0x86, 0x72, 0x5a, 0x85, 0x59, 0x73, 0x26, 0x27,
                        0x70, 0x2c, 0x2b, 0x7a
                    },
                    ExpectedData: new ApplicationUpdateRequestData(
                        Event: ApplicationUpdateEvent.NodeInfoReceived,
                        Generic: new ApplicationUpdateGenericData(
                            NodeId: 2,
                            BasicDeviceClass: 4,
                            GenericDeviceClass: 17,
                            SpecificDeviceClass: 1,
                            CommandClasses: new[]
                            {
                                new CommandClassInfo(CommandClassId.ZWavePlusInfo, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.Crc16Encapsulation, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.Version, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.ManufacturerSpecific, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.DeviceResetLocally, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.Association, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.AssociationGroupInformation, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.Powerlevel, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.MultilevelSwitch, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.AllSwitch, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.Configuration, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.SceneActuatorConfiguration, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.SceneActivation, IsSupported: true, IsControlled: false),
                                new CommandClassInfo(CommandClassId.FirmwareUpdateMetaData, IsSupported: true, IsControlled: false),
                            }),
                        SmartStartPrime: null,
                        SmartStartIncludedNodeInfo: null)
                )
            });
}
