﻿using ZWave.Serial;

namespace ZWave.Commands;

internal struct RequestNodeInfoRequest : ICommand<RequestNodeInfoRequest>
{
    public RequestNodeInfoRequest(DataFrame frame)
    {
        Frame = frame;
    }

    public static DataFrameType Type => DataFrameType.REQ;

    public static CommandId CommandId => CommandId.RequestNodeInfo;

    public DataFrame Frame { get; }

    public static RequestNodeInfoRequest Create(byte nodeId)
    {
        Span<byte> commandParameters = stackalloc byte[1];
        commandParameters[0] = nodeId; // TODO: This may be 16 bits if the node base type is set to 16 bit mode.

        var frame = DataFrame.Create(Type, CommandId, commandParameters);
        return new RequestNodeInfoRequest(frame);
    }

    public static RequestNodeInfoRequest Create(DataFrame frame) => new RequestNodeInfoRequest(frame);
}
