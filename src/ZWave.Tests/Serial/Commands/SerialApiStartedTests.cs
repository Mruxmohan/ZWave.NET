using ZWave.Serial.Commands;
using ZWave.Serial;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class SerialApiStartedTests : CommandTestBase
{
    private record SerialApiStartedRequestData(
        SerialApiStartedWakeUpReason WakeUpReason,
        bool WatchdogStarted,
        byte DeviceOptionMask,
        byte GenericDeviceType,
        byte SpecificDeviceType,
        ReadOnlyMemory<byte> CommandClasses,
        SerialApiStartedSupportedProtocols SupportedProtocols);

    [TestMethod]
    public void Request()
    {
        TestReceivableCommand<SerialApiStartedRequest, SerialApiStartedRequestData>(
            DataFrameType.REQ,
            CommandId.SerialApiStarted,
            new[]
            {
                (
                    CommandParameters: new byte[] { 0x05, 0x00, 0x01, 0x02, 0x01, 0x00 },
                    ExpectedData: new SerialApiStartedRequestData(
                        WakeUpReason: SerialApiStartedWakeUpReason.PowerUp,
                        WatchdogStarted: false,
                        DeviceOptionMask: 0x01,
                        GenericDeviceType: 0x02,
                        SpecificDeviceType: 0x01,
                        CommandClasses: ReadOnlyMemory<byte>.Empty,
                        SupportedProtocols: 0x00)
                ),

                // Synthetic test for CCs
                (
                    CommandParameters: new byte[] { 0x05, 0x00, 0x01, 0x02, 0x01, 0x03, 0x01, 0x02, 0x03 },
                    ExpectedData: new SerialApiStartedRequestData(
                        WakeUpReason: SerialApiStartedWakeUpReason.PowerUp,
                        WatchdogStarted: false,
                        DeviceOptionMask: 0x01,
                        GenericDeviceType: 0x02,
                        SpecificDeviceType: 0x01,
                        CommandClasses: new byte[] { 0x01, 0x02, 0x03 },
                        SupportedProtocols: 0x00)
                ),

                // Synthetic test for supported protocols
                (
                    CommandParameters: new byte[] { 0x05, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01 },
                    ExpectedData: new SerialApiStartedRequestData(
                        WakeUpReason: SerialApiStartedWakeUpReason.PowerUp,
                        WatchdogStarted: false,
                        DeviceOptionMask: 0x01,
                        GenericDeviceType: 0x02,
                        SpecificDeviceType: 0x01,
                        CommandClasses: ReadOnlyMemory<byte>.Empty,
                        SupportedProtocols: SerialApiStartedSupportedProtocols.ZWaveLongRange)
                ),
            });
    }
}
