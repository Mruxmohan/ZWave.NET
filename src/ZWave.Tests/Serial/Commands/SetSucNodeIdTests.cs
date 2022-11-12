using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class SetSucNodeIdTests : CommandTestBase
{
    private record SetSucNodeIdResponseData(byte SessionId, SetSucNodeIdStatus SetSucNodeIdStatus);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.SetSucNodeId,
            new[]
            {
                // Synthetic
                (
                    Request: SetSucNodeIdRequest.Create(
                        nodeId: 1,
                        enableSuc: true,
                        capabilities: SetSucNodeIdRequestCapabilities.SucFuncNodeIdServer,
                        transmissionOptions: TransmissionOptions.ACK | TransmissionOptions.AutoRoute | TransmissionOptions.Explore,
                        sessionId: 0x02),
                    ExpectedCommandParameters: new byte[] { 0x01, 0x01, 0x25, 0x01, 0x02 }
                ),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<SetSucNodeIdCallback, SetSucNodeIdResponseData>(
            DataFrameType.REQ,
            CommandId.SetSucNodeId,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x02, 0x05 },
                    ExpectedData: new SetSucNodeIdResponseData(
                        SessionId: 2,
                        SetSucNodeIdStatus: SetSucNodeIdStatus.Succeeded)
                )
            });
}
