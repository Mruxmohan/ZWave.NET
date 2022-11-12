using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class GetControllerCapabilitiesTests : CommandTestBase
{
    private record GetControllerCapabilitiesResponseData(ControllerCapabilities Capabilities);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.GetControllerCapabilities,
            new[]
            {
                (Request: GetControllerCapabilitiesRequest.Create(), ExpectedCommandParameters: Array.Empty<byte>()),
            });

    [TestMethod]
    public void Response()
        => TestReceivableCommand<GetControllerCapabilitiesResponse, GetControllerCapabilitiesResponseData>(
            DataFrameType.RES,
            CommandId.GetControllerCapabilities,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x1c },
                    ExpectedData: new GetControllerCapabilitiesResponseData(
                        Capabilities: ControllerCapabilities.SisIsPresent | ControllerCapabilities.WasRealPrimary | ControllerCapabilities.SucEnabled)
                )
            });
}
