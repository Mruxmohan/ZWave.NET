namespace ZWave.Serial.Commands;

internal struct SendDataRequest : IRequestWithCallback<SendDataRequest>
{
    public SendDataRequest(DataFrame frame)
    {
        Frame = frame;
    }

    public static DataFrameType Type => DataFrameType.REQ;

    public static CommandId CommandId => CommandId.SendData;

    public static bool ExpectsResponseStatus => true;

    public DataFrame Frame { get; }

    public byte SessionId => Frame.CommandParameters.Span[^1];

    public static SendDataRequest Create(
        byte nodeId,
        ReadOnlySpan<byte> data,
        TransmissionOptions transmissionOptions,
        byte sessionId)
    {
        Span<byte> commandParameters = stackalloc byte[4 + data.Length];
        commandParameters[0] = nodeId; // TODO: This may be 16 bits if the node base type is set to 16 bit mode.
        commandParameters[1] = (byte)data.Length;
        data.CopyTo(commandParameters.Slice(2, data.Length));
        commandParameters[2 + data.Length] = (byte)transmissionOptions;
        commandParameters[3 + data.Length] = sessionId;

        var frame = DataFrame.Create(Type, CommandId, commandParameters);
        return new SendDataRequest(frame);
    }

    public static SendDataRequest Create(DataFrame frame) => new SendDataRequest(frame);
}

internal struct SendDataCallback : ICommand<SendDataCallback>
{
    public SendDataCallback(DataFrame frame)
    {
        Frame = frame;
    }

    public static DataFrameType Type => DataFrameType.REQ;

    public static CommandId CommandId => CommandId.SendData;

    public DataFrame Frame { get; }

    public byte SessionId => Frame.CommandParameters.Span[0];

    public TransmissionStatus TransmissionStatus => (TransmissionStatus)Frame.CommandParameters.Span[1];

    public TransmissionStatusReport? TransmissionStatusReport
        => Frame.CommandParameters.Length > 2
            ? new TransmissionStatusReport(Frame.CommandParameters[2..])
            : null;

    public static SendDataCallback Create(DataFrame frame) => new SendDataCallback(frame);
}