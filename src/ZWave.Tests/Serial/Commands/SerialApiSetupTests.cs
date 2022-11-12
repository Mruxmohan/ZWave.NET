using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class SerialApiSetupTests : CommandTestBase
{
    private record SerialApiSetupGetSupportedCommandsResponseData(
        bool WasSubcommandSupported,
        HashSet<SerialApiSetupSubcommand> SupportedSubcommands);

    private record SerialApiSetupSetTxStatusReportResponseData(
        bool WasSubcommandSupported,
        bool Success);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.SerialApiSetup,
            new[]
            {
                (
                    Request: SerialApiSetupRequest.GetSupportedCommands(),
                    ExpectedCommandParameters: new byte[] { 0x01 }
                ),

                // Synthetic
                (
                    Request: SerialApiSetupRequest.SetTxStatusReport(enable: true),
                    ExpectedCommandParameters: new byte[] { 0x02, 0x01 }
                ),
            });

    [TestMethod]
    public void GetSupportedCommandsResponse()
        => TestReceivableCommand<SerialApiSetupGetSupportedCommandsResponse, SerialApiSetupGetSupportedCommandsResponseData>(
            DataFrameType.RES,
            CommandId.SerialApiSetup,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x01, 0x1e },
                    ExpectedData: new SerialApiSetupGetSupportedCommandsResponseData(
                        WasSubcommandSupported: true,
                        SupportedSubcommands: new HashSet<SerialApiSetupSubcommand>
                        {
                            SerialApiSetupSubcommand.GetSupportedCommands,
                            SerialApiSetupSubcommand.SetPowerlevel,
                            SerialApiSetupSubcommand.GetPowerlevel,
                            SerialApiSetupSubcommand.GetMaxPayloadSize,
                            SerialApiSetupSubcommand.GetRFRegion
                        })
                ),
            });

    [TestMethod]
    public void SetTxStatusReportResponse()
        => TestReceivableCommand<SerialApiSetupSetTxStatusReportResponse, SerialApiSetupSetTxStatusReportResponseData>(
            DataFrameType.RES,
            CommandId.SerialApiSetup,
            new[]
            {
                // Synthetic
                (
                    CommandParameters: new byte[] { 0x01, 0x01 },
                    ExpectedData: new SerialApiSetupSetTxStatusReportResponseData(
                        WasSubcommandSupported: true,
                        Success: true)
                ),
            });
}
