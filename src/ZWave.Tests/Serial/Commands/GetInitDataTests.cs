using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetInitDataTests : CommandTestBase
{
    private record GetInitDataResponseData(
        byte ApiVersion,
        GetInitDataCapabilities ApiCapabilities,
        HashSet<byte> NodeIds,
        byte ChipType,
        byte ChipVersion);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetInitData,
            new[]
            {
                (Request: GetInitDataRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetInitDataResponse, GetInitDataResponseData>(
            DataFrameType.RES,
            CommandId.GetInitData,
            new[]
            {
                (
                    CommandParameters: new byte[]
                    {
                        0x08, 0x08, 0x1d, 0x07, 0x5a, 0xae, 0xf9, 0x7b,
                        0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x05, 0x00
                    },
                    ExpectedData: new GetInitDataResponseData(
                        ApiVersion: 8,
                        ApiCapabilities: GetInitDataCapabilities.SisFunctionality,
                        NodeIds: new HashSet<byte> { 1, 2, 3, 10, 12, 13, 15, 18, 19, 20, 22, 24, 25, 28, 29, 30, 31, 32, 33, 34, 36, 37, 38, 39, 42, 44, 45 },
                        ChipType: 5,
                        ChipVersion: 0)
                )
            });
}
