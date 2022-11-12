using System.Buffers;

using Microsoft.Extensions.Logging;

namespace ZWave.Serial;

internal static class FrameParser
{
    /// <summary>
    /// Tries to parse a ZWave frame from the provided byte sequence.
    /// </summary>
    /// <param name="sequence">The byte sequence for which to parse a frame</param>
    /// <returns>
    /// True if a frame was successfully read. If false, the caller should
    /// disregard any change of position in the buffer.
    /// </returns>
    public static bool TryParseData(ILogger logger, ref ReadOnlySequence<byte> sequence, out Frame frame)
    {
        frame = default;

        if (sequence.IsEmpty)
        {
            // No data
            return false;
        }

        var reader = new SequenceReader<byte>(sequence);

        // Skip any invalid data
        if (!reader.TryReadToAny(out ReadOnlySequence<byte> skippedSequence, FrameHeader.ValidHeaders, advancePastDelimiter: false))
        {
            // We didn't find any valid data, so consume the entire sequence
            sequence = sequence.Slice(sequence.End);
            logger.LogSerialApiSkippedBytes(sequence.Length);
            return false;
        }

        if (skippedSequence.Length > 0)
        {
            logger.LogSerialApiSkippedBytes(skippedSequence.Length);
        }

        // Consume the invalid data regardless of whether we find the frame complete later.
        sequence = sequence.Slice(reader.Position);

        if (!reader.TryPeek(out byte frameHeader))
        {
            throw new InvalidDataException("Could not read frame header after reading it already.");
        }

        switch (frameHeader)
        {
            case FrameHeader.ACK:
            {
                frame = Frame.ACK;
                sequence = sequence.Slice(1);
                return true;
            }
            case FrameHeader.NAK:
            {
                frame = Frame.NAK;
                sequence = sequence.Slice(1);
                return true;
            }
            case FrameHeader.CAN:
            {
                frame = Frame.CAN;
                sequence = sequence.Slice(1);
                return true;
            }
            case FrameHeader.SOF:
            {
                if (!reader.TryPeek(1, out byte lengthByte))
                {
                    return false;
                }

                // The length doesn't include the SOF or checksum, so read 2 extra bytes
                int frameLength = lengthByte + 2;
                if (reader.Remaining < frameLength)
                {
                    return false;
                }

                var frameData = new byte[frameLength];
                if (!reader.TryCopyTo(frameData))
                {
                    throw new InvalidDataException($"Could not read {frameLength} bytes despite having {reader.Remaining} remaining bytes in the sequence");
                }

                // A complete data frame was read. Advance the sequence.
                sequence = sequence.Slice(frameLength);
                frame = new Frame(frameData);
                return true;
            }
            default:
            {
                throw new InvalidDataException("Sequence is not at frame header position despite already finding it.");
            }
        }
    }
}
