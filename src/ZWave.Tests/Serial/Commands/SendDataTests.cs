using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

[TestClass]
public class SendDataTests : CommandTestBase
{
    private record SendDataCallbackData(
        byte SessionId,
        TransmissionStatus TransmissionStatus,
        TransmissionStatusReportData? TransmissionStatusReport);

    private record TransmissionStatusReportData(
        TimeSpan? TransitTime,
        byte? NumRepeaters,
        RssiMeasurement? AckRssi,
        ReadOnlyMemory<RssiMeasurement> AckRepeaterRssi,
        byte? AckChannelNumber,
        byte? TransmitChannelNumber,
        byte? RouteSchemeState,
        ReadOnlyMemory<byte> LastRouteRepeaters,
        bool? Beam1000ms,
        bool? Beam250ms,
        TransmissionStatusReportLastRouteSpeed? LastRouteSpeed,
        byte? RoutingAttempts,
        byte? RouteFailedLastFunctionalNodeId,
        byte? RouteFailedFirstNonFunctionalNodeId,
        sbyte? TransmitPower,
        RssiMeasurement? MeasuredNoiseFloor,
        sbyte? DestinationAckTransmitPower,
        RssiMeasurement? DestinationAckMeasuredRssi,
        RssiMeasurement? DestinationAckMeasuredNoiseFloor);

    [TestMethod]
    public void Request()
        => TestSendableCommand(
            DataFrameType.REQ,
            CommandId.SendData,
            new[]
            {
                (
                    Request: SendDataRequest.Create(
                        nodeId: 2,
                        data: new byte[] { 0x03, 0x86, 0x13, 0x5e },
                        TransmissionOptions.ACK | TransmissionOptions.AutoRoute | TransmissionOptions.Explore,
                        sessionId: 1),
                    ExpectedCommandParameters: new byte[] { 0x02, 0x04, 0x03, 0x86, 0x13, 0x5e, 0x25, 0x01 }
                ),
            });

    [TestMethod]
    public void Callback()
        => TestReceivableCommand<SendDataCallback, SendDataCallbackData>(
            DataFrameType.REQ,
            CommandId.SendData,
            new[]
            {
                (
                    CommandParameters: new byte[]
                    {
                        0x01, 0x00, 0x00, 0x03, 0x00, 0xd5, 0x7f, 0x7f,
                        0x7f, 0x7f, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                        0x00, 0x03, 0x01, 0x00, 0x00
                    },
                    ExpectedData: new SendDataCallbackData(
                        SessionId: 1,
                        TransmissionStatus: TransmissionStatus.Ok,
                        TransmissionStatusReport: new TransmissionStatusReportData(
                            TransitTime: TimeSpan.FromMilliseconds(30),
                            NumRepeaters: 0,
                            AckRssi: new RssiMeasurement(-43),
                            AckRepeaterRssi: new RssiMeasurement[]
                            {
                                new RssiMeasurement(127),
                                new RssiMeasurement(127),
                                new RssiMeasurement(127),
                                new RssiMeasurement(127),
                            },
                            AckChannelNumber: 0,
                            TransmitChannelNumber: 0,
                            RouteSchemeState: 3,
                            LastRouteRepeaters: new byte[] { 0x00, 0x00, 0x00, 0x00 },
                            Beam1000ms: false,
                            Beam250ms: false,
                            LastRouteSpeed: TransmissionStatusReportLastRouteSpeed.ZWave100k,
                            RoutingAttempts: 1,
                            RouteFailedLastFunctionalNodeId: 0,
                            RouteFailedFirstNonFunctionalNodeId: 0,
                            TransmitPower: null,
                            MeasuredNoiseFloor: null,
                            DestinationAckTransmitPower: null,
                            DestinationAckMeasuredRssi: null,
                            DestinationAckMeasuredNoiseFloor: null))
                )
            });
}
