using System.Runtime.CompilerServices;
using ZWave.Serial.Commands;

namespace ZWave.Serial;

internal readonly struct DataFrame
{
    public DataFrame(ReadOnlyMemory<byte> data)
    {
        if (data.Span[0] != FrameHeader.SOF)
        {
            throw new ArgumentException($"Data did not start with the SOF byte ({FrameHeader.SOF}). Found {data.Span[0]}", nameof(data));
        }

        if (data.Span[1] != data.Length - 2)
        {
            throw new ArgumentException($"Data did not have expected value for the length byte ({data.Length - 2}). Found {data.Span[1]}", nameof(data));
        }

        Data = data;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public DataFrameType Type => (DataFrameType)Data.Span[2];

    public CommandId CommandId => (CommandId)Data.Span[3];

    public ReadOnlyMemory<byte> CommandParameters => Data[4..^1];

    public static DataFrame Create(DataFrameType type, CommandId commandId)
        => Create(type, commandId, ReadOnlySpan<byte>.Empty);

    public static DataFrame Create(DataFrameType type, CommandId commandId, ReadOnlySpan<byte> commandParameters)
    {
        byte[] data = new byte[5 + commandParameters.Length];
        data[0] = FrameHeader.SOF;
        data[1] = (byte)(data.Length - 2); // Frame length does not include the SOF or Checksum
        data[2] = (byte)type;
        data[3] = (byte)commandId;
        commandParameters.CopyTo(data.AsSpan()[4..]);
        data[data.Length - 1] = CalculateChecksum(data);
        return new DataFrame(data);
    }

    public bool IsChecksumValid()
    {
        byte expectedChecksum = CalculateChecksum(Data.Span);
        int checksum = Data.Span[Data.Length - 1];
        return checksum == expectedChecksum;
    }

    public override string ToString()
    {
        bool isChecksumValid = IsChecksumValid();

        // These are manually counted
        int literalLength = 48 + CommandParameters.Length;
        int formattedCount = 2 + CommandParameters.Length;
        if (!isChecksumValid)
        {
            literalLength += 17;
        }

        var handler = new DefaultInterpolatedStringHandler(literalLength, formattedCount);
        handler.AppendLiteral("DataFrame [Type=");
        handler.AppendFormatted(Type);
        handler.AppendLiteral(", CommandId=");
        handler.AppendFormatted(CommandId);
        handler.AppendLiteral(", CommandParameters=");
        for (int i = 0; i < CommandParameters.Length; i++)
        {
            if (i > 0)
            {
                handler.AppendLiteral(" ");
            }

            handler.AppendFormatted(CommandParameters.Span[i], "x2");
        }

        if (!isChecksumValid)
        {
            handler.AppendLiteral(", InvalidChecksum");
        }

        handler.AppendLiteral("]");
        return handler.ToStringAndClear();
    }

    private static byte CalculateChecksum(ReadOnlySpan<byte> data)
    {
        byte checksum = 0xFF;

        // The checksum calculation does not include the SOF or the checksum itself
        for (int i = 1; i < data.Length - 1; i++)
        {
            checksum ^= data[i];
        }

        return checksum;
    }
}
