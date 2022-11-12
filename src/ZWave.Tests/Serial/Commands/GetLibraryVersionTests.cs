using ZWave.Serial.Commands;
using ZWave.Serial;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetLibraryVersionTests : CommandTestBase
{
    private record GetLibraryVersionResponseData(string LibraryVersion, LibraryType LibraryType);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetLibraryVersion,
            new[]
            {
                (Request: GetLibraryVersionRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetLibraryVersionResponse, GetLibraryVersionResponseData>(
            DataFrameType.RES,
            CommandId.GetLibraryVersion,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x5a, 0x2d, 0x57, 0x61, 0x76, 0x65, 0x20, 0x36, 0x2e, 0x30, 0x37, 0x00, 0x01 },
                    ExpectedData: new GetLibraryVersionResponseData(
                        LibraryVersion: "Z-Wave 6.07",
                        LibraryType: LibraryType.StaticController)
                )
            });
}
