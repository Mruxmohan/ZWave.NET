using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetNodeProtocolInfoTests : CommandTestBase
{
    private record GetNodeProtocolInfoResponseData(
        bool IsListening,
        bool IsRouting,
        IReadOnlyList<int> SupportedSpeeds,
        byte ProtocolVersion,
        bool OptionalFunctionality,
        FrequentListeningMode FrequentListeningMode,
        bool SupportsBeaming,
        NodeType NodeType,
        bool HasSpecificDeviceClass,
        bool SupportsSecurity,
        byte BasicDeviceClass,
        byte GenericDeviceClass,
        byte SpecificDeviceClass);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetNodeProtocolInfo,
            new[]
            {
                (Request: GetNodeProtocolInfoRequest.Create(1), ExpectedCommandParameters: new byte[] { 0x01 }),
                (Request: GetNodeProtocolInfoRequest.Create(2), ExpectedCommandParameters: new byte[] { 0x02 }),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetNodeProtocolInfoResponse, GetNodeProtocolInfoResponseData>(
            DataFrameType.RES,
            CommandId.GetNodeProtocolInfo,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x93, 0x16, 0x01, 0x02, 0x02, 0x01 },
                    ExpectedData: new GetNodeProtocolInfoResponseData(
                        IsListening: true,
                        IsRouting: false,
                        SupportedSpeeds: new[] { 40000, 100000 },
                        ProtocolVersion: 3,
                        OptionalFunctionality: false,
                        FrequentListeningMode: FrequentListeningMode.None,
                        SupportsBeaming: true,
                        NodeType: NodeType.Controller,
                        HasSpecificDeviceClass: true,
                        SupportsSecurity: false,
                        BasicDeviceClass: 2,
                        GenericDeviceClass: 2,
                        SpecificDeviceClass: 1)
                ),
                (
                    CommandParameters: new byte[] { 0xd3, 0x9c, 0x01, 0x04, 0x11, 0x01 },
                    ExpectedData: new GetNodeProtocolInfoResponseData(
                        IsListening: true,
                        IsRouting: true,
                        SupportedSpeeds: new[] { 40000, 100000 },
                        ProtocolVersion: 3,
                        OptionalFunctionality: true,
                        FrequentListeningMode: FrequentListeningMode.None,
                        SupportsBeaming: true,
                        NodeType: NodeType.EndNode,
                        HasSpecificDeviceClass: true,
                        SupportsSecurity: false,
                        BasicDeviceClass: 4,
                        GenericDeviceClass: 17,
                        SpecificDeviceClass: 1)
                ),
            });
}
