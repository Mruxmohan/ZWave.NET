using System.Runtime.CompilerServices;

namespace ZWave.CommandClasses;

public abstract class CommandClass<TCommand> : CommandClass
    where TCommand : struct, Enum
{
    internal CommandClass(CommandClassInfo info, Driver driver, Node node)
        : base(info, driver, node)
    {
        if (Unsafe.SizeOf<TCommand>() != Unsafe.SizeOf<byte>())
        {
            throw new ArgumentException($"The generic type '{typeof(TCommand).Name}' must be an enum with backing type byte.");
        }
    }

    /// <summary>
    /// Determines whether a command is supported for calling.
    /// </summary>
    /// <remarks>
    /// If the return value is unknown, usually either the command class's version has not been queried yet
    /// or there is some prerequisite command to call to get the command class capabilitiles first.
    /// </remarks>
    /// <returns>True if the command is supported, false if not, null if unknown.</returns>
    public abstract bool? IsCommandSupported(TCommand command);

    protected override bool? IsCommandSupported(byte command)
        => IsCommandSupported(Unsafe.As<byte, TCommand>(ref command));
}

public abstract class CommandClass
{
    private record struct AwaitedReport(
        byte CommandId,
        Predicate<CommandClassFrame>? Predicate,
        TaskCompletionSource<CommandClassFrame> TaskCompletionSource);

    // Almost all CCs depend on knowing their own version.
    private static readonly CommandClassId[] DefaultDependencies = new[] { CommandClassId.Version };

    // We don't expect this to get very large at all, so using a simple list to save on memory instead
    // of Dictionary<CommandId, List<TCS>> which would have faster lookups
    private readonly List<AwaitedReport> _awaitedReports = new List<AwaitedReport>();

    internal CommandClass(
        CommandClassInfo info,
        Driver driver,
        Node node)
    {
        Info = info;
        Driver = driver;
        Node = node;
    }

    public CommandClassInfo Info { get; private set; }

    protected Driver Driver { get; }

    public Node Node { get; }

    public byte? Version { get; private set; }

    // If we don't know the version, we have to assume it's version 1
    protected byte EffectiveVersion => Version.GetValueOrDefault(1);

    internal void MergeInfo(CommandClassInfo info)
    {
        if (info.CommandClass != Info.CommandClass)
        {
            throw new ArgumentException($"Frame is for the wrong command class. Expected {Info.CommandClass} but found {info.CommandClass}.", nameof(info));
        }

        Info = new CommandClassInfo(
            info.CommandClass,
            info.IsSupported || Info.IsSupported,
            info.IsControlled || Info.IsControlled);
    }

    internal void SetVersion(byte version)
    {
        Version = version;
    }

    internal abstract Task InterviewAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Gets a list of command classes which must be interviewed before this one.
    /// </summary>
    internal virtual CommandClassId[] Dependencies => DefaultDependencies;

    protected abstract bool? IsCommandSupported(byte command);

    internal void ProcessCommand(CommandClassFrame frame)
    {
        if (frame.CommandClassId != Info.CommandClass)
        {
            throw new ArgumentException($"Frame is for the wrong command class. Expected {Info.CommandClass} but found {frame.CommandClassId}.", nameof(frame));
        }

        ProcessCommandCore(frame);

        lock (_awaitedReports)
        {
            int i = 0;
            while (i < _awaitedReports.Count)
            {
                AwaitedReport awaitedReport = _awaitedReports[i];
                if (awaitedReport.CommandId == frame.CommandId
                    && (awaitedReport.Predicate == null || awaitedReport.Predicate(frame)))
                {
                    awaitedReport.TaskCompletionSource.TrySetResult(frame);
                    _awaitedReports.RemoveAt(i);
                }
                else
                {
                    i++;
                }
            }
        }
    }

    protected abstract void ProcessCommandCore(CommandClassFrame frame);

    internal async Task SendCommandAsync<TRequest>(
        TRequest command,
        CancellationToken cancellationToken)
        where TRequest : struct, ICommand
    {
        if (!IsCommandSupported(TRequest.CommandId).GetValueOrDefault())
        {
            throw new ZWaveException(ZWaveErrorCode.CommandNotSupported, "This command is not supported by this node");
        }

        await Driver.SendCommandAsync(command, Node.Id, cancellationToken).ConfigureAwait(false);
    }

    internal Task<CommandClassFrame> AwaitNextReportAsync<TReport>(CancellationToken cancellationToken)
        where TReport : struct, ICommand
        => AwaitNextReportAsync<TReport>(predicate: null, cancellationToken);

    internal async Task<CommandClassFrame> AwaitNextReportAsync<TReport>(
        Predicate<CommandClassFrame>? predicate,
        CancellationToken cancellationToken)
        where TReport : struct, ICommand
    {
        if (TReport.CommandClassId != Info.CommandClass)
        {
            throw new ArgumentException($"Report is for the wrong command class. Expected {Info.CommandClass} but found {TReport.CommandClassId}.", nameof(TReport));
        }

        var tcs = new TaskCompletionSource<CommandClassFrame>();
        var awaitedReport = new AwaitedReport(TReport.CommandId, predicate, tcs);
        lock (_awaitedReports)
        {
            _awaitedReports.Add(awaitedReport);
        }

        using (cancellationToken.Register(static state => ((TaskCompletionSource<CommandClassFrame>)state!).TrySetCanceled(), tcs))
        {
            return await tcs.Task;
        }
    }
}
