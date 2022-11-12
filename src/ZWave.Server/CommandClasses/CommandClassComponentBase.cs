using Microsoft.AspNetCore.Components;

namespace ZWave.Server.CommandClasses;

public class CommandClassComponentBase : ComponentBase
{
    protected string? ErrorMessage { get; private set; }

    protected Exception? ErrorException { get; private set; }

    protected async Task RunSafelyAsync(Func<Task> action, string methodName)
    {
        ClearError();
        try
        {
            await action();
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error calling {methodName}";
            ErrorException = ex;
        }
    }

    private void ClearError()
    {
        ErrorMessage = null;
        ErrorException = null;
    }
}
