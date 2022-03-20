namespace ZWave;

internal static class BinaryExtensions
{
    public static sbyte ToInt8(this byte b) => unchecked((sbyte)b);

    public static ushort ToUInt16BE(this ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > sizeof(ushort))
        {
            throw new ArgumentException($"The number of bytes ({bytes.Length}) is more than can fit in an ushort ({sizeof(ushort)}).", nameof(bytes));
        }

        // BitConverter uses the endianness of the machine, so figure out if we have to reverse the bytes.
        if (BitConverter.IsLittleEndian)
        {
            // Note: There is no need to pad since LE would be padded on the right.
            Span<byte> buffer = stackalloc byte[sizeof(ushort)];
            bytes.CopyTo(buffer);
            buffer.Reverse();
            return BitConverter.ToUInt16(buffer);
        }
        else if (bytes.Length < sizeof(ushort))
        {
            // Add padding
            Span<byte> buffer = stackalloc byte[sizeof(ushort)];
            bytes.CopyTo(buffer.Slice(sizeof(ushort) - bytes.Length));
            return BitConverter.ToUInt16(buffer);
        }
        else
        {
            // Perfect size and endianness
            return BitConverter.ToUInt16(bytes);
        }
    }

    public static void WriteBytesBE(this ushort value, Span<byte> destination)
    {
        if (destination.Length != sizeof(ushort))
        {
            throw new ArgumentException($"Destination must be of length {sizeof(ushort)}");
        }

        if (!BitConverter.TryWriteBytes(destination, value))
        {
            // This really should never happen.
            throw new InvalidOperationException($"Value {value} could not be converted to bytes.");
        }

        // BitConverter uses the endianness of the machine, so figure out if we have to reverse the bytes.
        if (BitConverter.IsLittleEndian)
        {
            destination.Reverse();
        }
    }

    public static uint ToUInt32BE(this ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > sizeof(uint))
        {
            throw new ArgumentException($"The number of bytes ({bytes.Length}) is more than can fit in an uint ({sizeof(uint)}).", nameof(bytes));
        }

        // BitConverter uses the endianness of the machine, so figure out if we have to reverse the bytes.
        if (BitConverter.IsLittleEndian)
        {
            // Note: There is no need to pad since LE would be padded on the right.
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            bytes.CopyTo(buffer);
            buffer.Reverse();
            return BitConverter.ToUInt32(buffer);
        }
        else if (bytes.Length < sizeof(uint))
        {
            // Add padding
            Span<byte> buffer = stackalloc byte[sizeof(uint)];
            bytes.CopyTo(buffer.Slice(sizeof(uint) - bytes.Length));
            return BitConverter.ToUInt32(buffer);
        }
        else
        {
            // Perfect size and endianness
            return BitConverter.ToUInt32(bytes);
        }
    }

    public static void WriteBytesBE(this uint value, Span<byte> destination)
    {
        if (destination.Length != sizeof(uint))
        {
            throw new ArgumentException($"Destination must be of length {sizeof(uint)}");
        }

        if (!BitConverter.TryWriteBytes(destination, value))
        {
            // This really should never happen.
            throw new InvalidOperationException($"Value {value} could not be converted to bytes.");
        }

        // BitConverter uses the endianness of the machine, so figure out if we have to reverse the bytes.
        if (BitConverter.IsLittleEndian)
        {
            destination.Reverse();
        }
    }

    public static int ToInt32BE(this ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > sizeof(int))
        {
            throw new ArgumentException($"The number of bytes ({bytes.Length}) is more than can fit in an int ({sizeof(int)}).", nameof(bytes));
        }

        // BitConverter uses the endianness of the machine, so figure out if we have to reverse the bytes.
        if (BitConverter.IsLittleEndian)
        {
            // Note: There is no need to pad since LE would be padded on the right.
            Span<byte> buffer = stackalloc byte[sizeof(int)];
            bytes.CopyTo(buffer);
            buffer.Reverse();
            return BitConverter.ToInt32(buffer);
        }
        else if (bytes.Length < sizeof(int))
        {
            // Add padding
            Span<byte> buffer = stackalloc byte[sizeof(int)];
            bytes.CopyTo(buffer.Slice(sizeof(int) - bytes.Length));
            return BitConverter.ToInt32(buffer);
        }
        else
        {
            // Perfect size and endianness
            return BitConverter.ToInt32(bytes);
        }
    }
}
