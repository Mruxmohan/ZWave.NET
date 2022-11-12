using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class ResponseStatusTests : CommandTestBase
{
    private record ResponseStatusResponseData(bool WasRequestAccepted);

    [TestMethod]
    public void Response()
        => TestReceivableCommand<ResponseStatusResponse, ResponseStatusResponseData>(
            DataFrameType.RES,
            0, // Throws
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x01 },
                    ExpectedData: new ResponseStatusResponseData(WasRequestAccepted: true)
                )
            });
}
