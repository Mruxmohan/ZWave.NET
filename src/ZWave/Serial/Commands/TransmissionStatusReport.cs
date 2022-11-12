namespace ZWave.Serial.Commands;

internal enum TransmissionStatusReportLastRouteSpeed : byte
{
    /// <summary>
    /// Z-Wave 9.6 kbits/s
    /// </summary>
    ZWave9k6 = 0x01,

    /// <summary>
    /// Z-Wave 40 kbits/s
    /// </summary>
    ZWave40k = 0x02,

    /// <summary>
    /// Z-Wave 100 kbits/s
    /// </summary>
    ZWave100k = 0x03,

    /// <summary>
    /// Z-Wave Long Range 100 kbits/s
    /// </summary>
    ZWaveLongRange100k = 0x04,
}

/// <summary>
/// Provides details about the transmission that was carried out.
/// </summary>
/// <remarks>
/// From the spec:
///     The Tx Status Report is a variable length field that has grown through the revisions of the Z-Wave API.
///     A host application MUST be resistant to unexpected length of this field (both shorter and longer).
/// The spec doesn't define just how short we need to be resilient to, so consider *all* fields optional.
/// </remarks>
internal readonly struct TransmissionStatusReport
{
    private readonly ReadOnlyMemory<byte> _data;

    public TransmissionStatusReport(ReadOnlyMemory<byte> data)
    {
        _data = data;
    }

    /// <summary>
    /// The transmission time.
    /// </summary>
    public TimeSpan? TransitTime
        => _data.Length > 1
            // The data is in multiples of 10ms
            ? TimeSpan.FromMilliseconds(10 * _data.Span[0..2].ToUInt16BE())
            : null;

    /// <summary>
    /// The number of repeaters used in the route to the destination
    /// </summary>
    public byte? NumRepeaters
        => _data.Length > 2
            ? _data.Span[2]
            : null;

    /// <summary>
    /// The RSSI value of the acknowledgement frame.
    /// </summary>
    public RssiMeasurement? AckRssi
        => _data.Length > 3
            ? _data.Span[3]
            : null;

    /// <summary>
    /// The RSSI value measured from Repeaters for the incoming Acknowledgement frame.
    /// </summary>
    public ReadOnlyMemory<RssiMeasurement> AckRepeaterRssi
    {
        get
        {
            if (_data.Length < 8)
            {
                return ReadOnlyMemory<RssiMeasurement>.Empty;
            }

            var result = new RssiMeasurement[4];
            result[0] = _data.Span[4];
            result[1] = _data.Span[5];
            result[2] = _data.Span[6];
            result[3] = _data.Span[7];
            return result;
        }
    }

    /// <summary>
    /// The channel number where the ACK received from
    /// </summary>
    public byte? AckChannelNumber
        => _data.Length > 8
            ? _data.Span[8]
            : null;

    /// <summary>
    /// The channel number that is used to transmit the data
    /// </summary>
    public byte? TransmitChannelNumber
        => _data.Length > 9
            ? _data.Span[9]
            : null;

    /// <summary>
    /// The state of the route resolution for the transmission attempt
    /// </summary>
    public byte? RouteSchemeState
        => _data.Length > 10
            ? _data.Span[10]
            : null;

    /// <summary>
    /// The repeaters used in the route to communicate with the destination.
    /// </summary>
    public ReadOnlyMemory<byte> LastRouteRepeaters
        => _data.Length > 14
            ? _data[11..15]
            : ReadOnlyMemory<byte>.Empty;

    /// <summary>
    /// Whether the destination requires a 1000ms beam (or a fragmented beam) to be reached.
    /// </summary>
    public bool? Beam1000ms
        => _data.Length > 15
            ? (_data.Span[15] & 0b0100_0000) != 0
            : null;

    /// <summary>
    /// Whether the destination requires a 250ms beam to be reached.
    /// </summary>
    public bool? Beam250ms
        => _data.Length > 15
            ? (_data.Span[15] & 0b0010_0000) != 0
            : null;

    /// <summary>
    /// The transmission speed used in the route to communicate with the destination.
    /// </summary>
    public TransmissionStatusReportLastRouteSpeed? LastRouteSpeed
        => _data.Length > 15
            ? (TransmissionStatusReportLastRouteSpeed)(_data.Span[15] & 0b0000_0111)
            : null;

    /// <summary>
    /// How many routing attempts have been made to transmit the payload to the destination NodeID.
    /// </summary>
    public byte? RoutingAttempts
        => _data.Length > 16
            ? _data.Span[16]
            : null;

    /// <summary>
    /// When a route failed, indicates the last functional NodeID in the last used route.
    /// </summary>
    public byte? RouteFailedLastFunctionalNodeId
        => _data.Length > 17
            ? _data.Span[17]
            : null;

    /// <summary>
    /// When a route failed, indicates the first non-functional NodeID in the last used route.
    /// </summary>
    public byte? RouteFailedFirstNonFunctionalNodeId
        => _data.Length > 18
            ? _data.Span[18]
            : null;

    /// <summary>
    /// The transmit power used for the transmission in dBm.
    /// </summary>
    public sbyte? TransmitPower
    {
        get
        {
            if (_data.Length < 20)
            {
                return null;
            }

            var value = _data.Span[19].ToInt8();

            // From the spec: The value 127 MUST indicate that the value is not available.
            return value == 127
                ? null
                : value;
        }
    }

    /// <summary>
    /// When a route failed, indicates the first non-functional NodeID in the last used route.
    /// </summary>
    public RssiMeasurement? MeasuredNoiseFloor
        => _data.Length > 20
            ? _data.Span[20]
            : null;

    /// <summary>
    /// The transmit Power used by the destination in its Ack MPDU frame in dBm.
    /// </summary>
    public sbyte? DestinationAckTransmitPower
    {
        get
        {
            if (_data.Length < 22)
            {
                return null;
            }

            var value = _data.Span[21].ToInt8();

            // From the spec: The value 127 MUST indicate that the value is not available.
            return value == 127
                ? null
                : value;
        }
    }

    /// <summary>
    /// The measured RSSI of the acknowledgement frame received from the destination.
    /// </summary>
    public RssiMeasurement? DestinationAckMeasuredRssi
        => _data.Length > 22
                ? _data.Span[22]
                : null;

    /// <summary>
    /// The measured noise floor by the destination during the MDPU Ack frame transmission.
    /// </summary>
    public RssiMeasurement? DestinationAckMeasuredNoiseFloor
        => _data.Length > 23
            ? _data.Span[23]
            : null;
}
