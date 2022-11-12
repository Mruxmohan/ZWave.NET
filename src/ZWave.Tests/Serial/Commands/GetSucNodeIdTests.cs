using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetSucNodeIdTests : CommandTestBase
{
    private record GetSucNodeIdResponseData(byte SucNodeId);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetSucNodeId,
            new[]
            {
                (Request: GetSucNodeIdRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetSucNodeIdResponse, GetSucNodeIdResponseData>(
            DataFrameType.RES,
            CommandId.GetSucNodeId,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x01 },
                    ExpectedData: new GetSucNodeIdResponseData(SucNodeId: 1)
                )
            });
}
