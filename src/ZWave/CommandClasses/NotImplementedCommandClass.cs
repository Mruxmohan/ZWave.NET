namespace ZWave.CommandClasses;

public enum NotImplementedCommand : byte
{
}

/// <summary>
/// Represents a command class which hasn't been implemented by this library yet.
/// </summary>
public sealed class NotImplementedCommandClass : CommandClass<NotImplementedCommand>
{
    internal NotImplementedCommandClass(CommandClassInfo info, Driver driver, Node node) : base(info, driver, node)
    {
    }

    /// <inheritdoc />
    public override bool? IsCommandSupported(NotImplementedCommand command) => false;

    internal override Task InterviewAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    protected override void ProcessCommandCore(CommandClassFrame frame)
    {
    }
}
