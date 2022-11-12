using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class ApplicationCommandHandlerTests : CommandTestBase
{
    private record ApplicationCommandHandlerData(
        ReceivedStatus ReceivedStatus,
        byte NodeId,
        ReadOnlyMemory<byte> Payload,
        RssiMeasurement ReceivedRssi);

    [TestMethod]
    public void Command()
        => TestReceivableCommand<ApplicationCommandHandler, ApplicationCommandHandlerData>(
            DataFrameType.REQ,
            CommandId.ApplicationCommandHandler,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x00, 0x02, 0x04, 0x86, 0x14, 0x5e, 0x02, 0xd5, 0x00 },
                    ExpectedData: new ApplicationCommandHandlerData(
                        ReceivedStatus: 0,
                        NodeId: 2,
                        Payload: new byte[] { 0x86, 0x14, 0x5e, 0x02 },
                        ReceivedRssi: new RssiMeasurement(-43))
                ),
                (
                    CommandParameters: new byte[] { 0x00, 0x2c, 0x0e, 0x32, 0x02, 0x21, 0x64, 0x00, 0x08, 0x83, 0xd6, 0x00, 0x1b, 0x00, 0x08, 0x83, 0xcb, 0xbf, 0x00 },
                    ExpectedData: new ApplicationCommandHandlerData(
                        ReceivedStatus: 0,
                        NodeId: 44,
                        Payload: new byte[] { 0x32, 0x02, 0x21, 0x64, 0x00, 0x08, 0x83, 0xd6, 0x00, 0x1b, 0x00, 0x08, 0x83, 0xcb },
                        ReceivedRssi: new RssiMeasurement(-65))
                ),
            });
}
