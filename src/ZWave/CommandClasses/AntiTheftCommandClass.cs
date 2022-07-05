namespace ZWave.CommandClasses;

public enum AntiTheftCommand : byte
{ 
    /// <summary>
    /// Lock or unlock a device.
    /// </summary>
    Set = 0x01,

    /// <summary>
    /// Request the locked or unlocked state of a supporting device.
    /// </summary>
    Get = 0x02,

    /// <summary>
    /// Advertise the lock or unlock state of a supporting device.
    /// </summary>
    Report = 0x03
}

public enum AntiTheftProtectionStatus : byte
{
    /// <summary>
    /// Anti-theft protection is disabled, the node is unlocked.
    /// </summary>
    Unlocked = 0x01,

    /// <summary>
    /// Anti-theft protection is enabled, the node is locked. Network did not change, so this is fully functional.
    /// </summary>
    Locked = 0x02,

    /// <summary>
    /// Anti-theft protection is enabled, the node is locked. However, the node either reset or changed network, so it runs in restricted mode.
    /// </summary>
    Restricted = 0x03,
}

[CommandClass(CommandClassId.AntiTheft)]
public sealed class AntiTheftCommandClass : CommandClass<AntiTheftCommand>
{
    public AntiTheftCommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
    }

    public AntiTheftProtectionStatus? State { get; private set; }

    public override bool? IsCommandSupported(AntiTheftCommand command)
        => command switch
        {
            AntiTheftCommand.Set => true,
            AntiTheftCommand.Get => true,
            AntiTheftCommand.Report => true,
            _ => false
        };

    public async Task SetAsync(
        byte version,
        bool state,
        byte[] magicCode,
        ushort manufacturerId,
        byte[] hint,
        ushort? allianceLockingEntityId,
        CancellationToken cancellationToken)
    {
        var command = AntiTheftSetCommand.Create(
            version,
            state,
            stackalloc byte[magicCode.Length],
            manufacturerId,
            stackalloc byte[hint.Length],
            allianceLockingEntityId);

        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Request the locked or unlocked state of a supporting node.
    /// </summary>
    public async Task<AntiTheftProtectionStatus> GetAsync(CancellationToken cancellationToken)
    {
        var command = AntiTheftGetCommand.Create();
        await SendCommandAsync(command, cancellationToken).ConfigureAwait(false);
        await AwaitNextReportAsync<AntiTheftReportCommand>(cancellationToken).ConfigureAwait(false);
        return State!.Value;
    }

    protected override async Task InterviewCoreAsync(CancellationToken cancellationToken)
    {
        _ = await GetAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
        switch ((AntiTheftCommand)frame.CommandId)
        {
            case AntiTheftCommand.Set:
            case AntiTheftCommand.Get:
            {
                // We don't expect to recieve these commands
                break;
            }
            case AntiTheftCommand.Report:
            {
                var command = new AntiTheftReportCommand(frame, Version);
                State = command.ProtectionStatus;
                break;
            }
        }
    }

    private struct AntiTheftSetCommand : ICommand
    {
        public AntiTheftSetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.AntiTheft;

        public static byte CommandId => (byte)AntiTheftCommand.Set;

        public CommandClassFrame Frame { get; }

        public static AntiTheftSetCommand Create(
            byte version,
            bool state,
            ReadOnlySpan<byte> magicCode,
            ushort manufacturerId,
            ReadOnlySpan<byte> hint,
            ushort? allianceLockingEntityId)
        {
            if (magicCode.Length is > 10 or < 1)
            {
                throw new ArgumentException("Magic code length must fall in the range [1,10].");
            }
            else if (hint.Length is > 10 or < 0)
            {
                throw new ArgumentException("Hint code length must fall in the range [0,10].");
            }

            Span<byte> commandParameters = stackalloc byte[magicCode.Length + hint.Length + (version >= 3 ? 6 : 4)];
            commandParameters[0] = (byte)(state ? 0x80 | magicCode.Length : 0x7f & magicCode.Length);

            var endOffset = magicCode.Length + 1;
            magicCode[0..].CopyTo(commandParameters[1..endOffset++]);

            // Manufacturer id must be set to 0x00 by sending node if state field is set to 0
            var startOffset = endOffset++;
            Span<byte> manufacturerBytes = stackalloc byte[2];
            if (state)
            {
                manufacturerId.WriteBytesBE(manufacturerBytes);
            }

            manufacturerBytes.CopyTo(commandParameters[startOffset..endOffset++]);

            // Hint must be omitted if hint length is set to 0
            startOffset = endOffset;
            commandParameters[startOffset] = (byte)hint.Length;
            if (hint.Length > 0)
            {
                startOffset = endOffset + 1;
                endOffset = hint.Length + startOffset;
                hint[0..].CopyTo(commandParameters[startOffset..endOffset]);
            }

            if (version >= 3)
            {
                startOffset = endOffset++ + 1;
                Span<byte> allianceBytes = stackalloc byte[2];
                if (state)
                {
                    if (allianceLockingEntityId == 0)
                    {
                        throw new ArgumentException("Alliance locking entity id must not be set to zero for non-zero state.");
                    }

                    allianceLockingEntityId?.WriteBytesBE(allianceBytes);
                }

                allianceBytes.CopyTo(commandParameters[startOffset..endOffset]);
            }

            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId, commandParameters);
            return new AntiTheftSetCommand(frame);
        }
    }

    private struct AntiTheftGetCommand : ICommand
    {
        public AntiTheftGetCommand(CommandClassFrame frame)
        {
            Frame = frame;
        }

        public static CommandClassId CommandClassId => CommandClassId.AntiTheft;

        public static byte CommandId => (byte)AntiTheftCommand.Get;

        public CommandClassFrame Frame { get; }

        public static AntiTheftGetCommand Create()
        {
            CommandClassFrame frame = CommandClassFrame.Create(CommandClassId, CommandId);
            return new AntiTheftGetCommand(frame);
        }
    }

    private struct AntiTheftReportCommand : ICommand
    {
        private readonly byte? _version;

        public AntiTheftReportCommand(CommandClassFrame frame, byte? version)
        {
            Frame = frame;
            _version = version;
        }

        public static CommandClassId CommandClassId => CommandClassId.AntiTheft;

        public static byte CommandId => (byte)AntiTheftCommand.Report;

        public CommandClassFrame Frame { get; }

        public AntiTheftProtectionStatus? ProtectionStatus => (AntiTheftProtectionStatus)Frame.CommandParameters.Span[0];

        /// <summary>
        /// Z-Wave manufacturer id of the company's product that has locked the device.
        /// </summary>
        public ushort ManufacturerId => Frame.CommandParameters.Length > 2
            ? ProtectionStatus == AntiTheftProtectionStatus.Unlocked
                ? (ushort)0x00
                : Frame.CommandParameters.Span[1..2].ToUInt16BE()
            : throw new ArgumentException("Two bytes must be allocated for the manufacturer id.");

        /// <summary>
        /// Indicates the length, in range [1, 10], of the hint in bytes.
        /// </summary>
        public int HintLength => Frame.CommandParameters.Length > 3
            ? ProtectionStatus == AntiTheftProtectionStatus.Unlocked
                ? 0
                : Frame.CommandParameters.Span[3].ToInt8() is >= 0 and <= 10
                    ? Frame.CommandParameters.Span[3].ToInt8()
                    : throw new ArgumentException("Values for hint length must fall into the range [0, 10].")
            : throw new ArgumentException("Not enough bytes allocated for hint length");

        /// <summary>
        /// Identifier used to help retrieve the magic code.    
        /// </summary>
        public ReadOnlySpan<byte> Hint => (Frame.CommandParameters.Length > HintLength + 4) && (HintLength > 0)
            ? Frame.CommandParameters.Span.Slice(4, HintLength)
            : null;

        /// <summary>
        /// Unique id for the entity that has locked the device.
        /// </summary>
        public ushort? AllianceLockingEntityId => _version >= 3 && Frame.CommandParameters.Length > HintLength + 6
            ? ProtectionStatus == AntiTheftProtectionStatus.Unlocked
                ? (ushort)0x00
                : Frame.CommandParameters.Span.Slice(HintLength + 4, 2).ToUInt16BE()
            : null;
    }
}