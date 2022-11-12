using ZWave.Serial.Commands;
using ZWave.Serial;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class MemoryGetIdTests : CommandTestBase
{
    private record MemoryGetIdResponseData(uint HomeId, byte NodeId);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.MemoryGetId,
            new[]
            {
                (Request: MemoryGetIdRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<MemoryGetIdResponse, MemoryGetIdResponseData>(
            DataFrameType.RES,
            CommandId.MemoryGetId,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x2f, 0x3b, 0xd8, 0x2a, 0x01 },
                    ExpectedData: new MemoryGetIdResponseData(HomeId: 792451114u, NodeId: 1)
                )
            });
}
