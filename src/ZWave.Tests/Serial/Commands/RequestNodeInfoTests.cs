using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class RequestNodeInfoTests : CommandTestBase
{
    private record RequestNodeInfoResponseData(ControllerCapabilities Capabilities);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.RequestNodeInfo,
            new[]
            {
                (Request: RequestNodeInfoRequest.Create(2), ExpectedCommandParameters: new byte[] { 0x02 }),
            });
}
