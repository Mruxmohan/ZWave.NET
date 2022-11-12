using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using ZWave.CommandClasses;
using ZWave.Serial.Commands;

namespace ZWave;

public sealed class Node
{
    private readonly Driver _driver;

    private readonly ILogger _logger;

    private readonly AsyncAutoResetEvent _nodeInfoRecievedEvent = new AsyncAutoResetEvent();

    private readonly Dictionary<CommandClassId, CommandClass> _commandClasses = new Dictionary<CommandClassId, CommandClass>();

    private readonly object _interviewStateLock = new object();

    private Task? _interviewTask;

    private CancellationTokenSource? _interviewCancellationTokenSource;

    internal Node(byte id, Driver driver, ILogger logger)
    {
        Id = id;
        _driver = driver ?? throw new ArgumentNullException(nameof(driver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public byte Id { get; }

    public NodeInterviewStatus InterviewStatus { get; private set; }

    public bool IsListening { get; private set; }

    public bool IsRouting { get; private set; }

    public IReadOnlyList<int> SupportedSpeeds { get; private set; } = Array.Empty<int>();

    public byte ProtocolVersion { get; private set; }

    public NodeType NodeType { get; private set; }

    public FrequentListeningMode FrequentListeningMode { get; private set; }

    public bool SupportsBeaming { get; private set; }

    public bool SupportsSecurity { get; private set; }

    public IReadOnlyDictionary<CommandClassId, CommandClassInfo> CommandClasses
    {
        get
        {
            Dictionary<CommandClassId, CommandClassInfo> commandClassInfos;
            lock (_commandClasses)
            {
                commandClassInfos = new Dictionary<CommandClassId, CommandClassInfo>(_commandClasses.Count);
                foreach (KeyValuePair<CommandClassId, CommandClass> pair in _commandClasses)
                {
                    commandClassInfos.Add(pair.Key, pair.Value.Info);
                }
            }

            return commandClassInfos;
        }
    }

    public TCommandClass GetCommandClass<TCommandClass>()
        where TCommandClass : CommandClass
        => (TCommandClass)GetCommandClass(CommandClassFactory.GetCommandClassId<TCommandClass>());

    public bool TryGetCommandClass<TCommandClass>([NotNullWhen(true)]out TCommandClass? commandClass)
        where TCommandClass : CommandClass
    {
        if (TryGetCommandClass(CommandClassFactory.GetCommandClassId<TCommandClass>(), out CommandClass? commandClassBase))
        {
            commandClass = (TCommandClass)commandClassBase;
            return true;
    }
        else
        {
            commandClass = null;
            return false;
        }
    }

    public CommandClass GetCommandClass(CommandClassId commandClassId)
        => !TryGetCommandClass(commandClassId, out CommandClass? commandClass)
            ? throw new ZWaveException(ZWaveErrorCode.CommandClassNotImplemented, $"The command class {commandClassId} is not implemented by this node.")
            : commandClass;

    public bool TryGetCommandClass(CommandClassId commandClassId, [NotNullWhen(true)] out CommandClass? commandClass)
    {
        lock (_commandClasses)
        {
            return _commandClasses.TryGetValue(commandClassId, out commandClass);
        }
    }

    /// <summary>
    /// Interviews the node.
    /// </summary>
    /// <remarks>
    /// the interview may take a very long time, so the returned task should generally not be awaited.
    /// </remarks>
    public async Task InterviewAsync(CancellationToken cancellationToken)
    {
        Task interviewTask;
        lock (_interviewStateLock)
        {
            InterviewStatus = NodeInterviewStatus.None;

            // Cancel any previous interview
            _interviewCancellationTokenSource?.Cancel();
            Task? previousInterviewTask = _interviewTask;

            _interviewCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _interviewTask = interviewTask = Task.Run(async () =>
            {
                CancellationToken cancellationToken = _interviewCancellationTokenSource.Token;

                // Wait for any previous interview to stop
                if (previousInterviewTask != null)
                {
                    try
                    {
                        await previousInterviewTask.ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // Swallow the cancellation as we just cancelled it.
                    }
                }

                // Reset the status again in case the previous interview task modified it.
                InterviewStatus = NodeInterviewStatus.None;

                var getNodeProtocolInfoRequest = GetNodeProtocolInfoRequest.Create(Id);
                GetNodeProtocolInfoResponse getNodeProtocolInfoResponse = await _driver.SendCommandAsync<GetNodeProtocolInfoRequest, GetNodeProtocolInfoResponse>(
                    getNodeProtocolInfoRequest,
                    cancellationToken).ConfigureAwait(false);
                IsListening = getNodeProtocolInfoResponse.IsListening;
                IsRouting = getNodeProtocolInfoResponse.IsRouting;
                SupportedSpeeds = getNodeProtocolInfoResponse.SupportedSpeeds;
                ProtocolVersion = getNodeProtocolInfoResponse.ProtocolVersion;
                NodeType = getNodeProtocolInfoResponse.NodeType;
                FrequentListeningMode = getNodeProtocolInfoResponse.FrequentListeningMode;
                SupportsBeaming = getNodeProtocolInfoResponse.SupportsBeaming;
                SupportsSecurity = getNodeProtocolInfoResponse.SupportsSecurity;
                // TODO: Log

                InterviewStatus = NodeInterviewStatus.ProtocolInfo;

                // This is all we need for the controller node
                if (Id == _driver.Controller.NodeId)
                {
                    InterviewStatus = NodeInterviewStatus.Complete;
                    return;
                }

                // This request causes unsolicited requests from the controller (kind of like a callback) with command id ApplicationControllerUpdate
                var requestNodeInfoRequest = RequestNodeInfoRequest.Create(Id);
                int requestNodeInfoRequestNum = 0;
                ResponseStatusResponse requestNodeInfoResponse;
                do
                {
                    requestNodeInfoResponse = await _driver.SendCommandAsync<RequestNodeInfoRequest, ResponseStatusResponse>(requestNodeInfoRequest, cancellationToken)
                        .ConfigureAwait(false);

                    if (requestNodeInfoRequestNum > 0)
                    {
                        await Task.Delay(100 * requestNodeInfoRequestNum);
                    }

                    requestNodeInfoRequestNum++;
                }
                while (!requestNodeInfoResponse.WasRequestAccepted); // If the command is rejected, retry.

                await _nodeInfoRecievedEvent.WaitAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
                InterviewStatus = NodeInterviewStatus.NodeInfo;

                await InterviewCommandClassesAsync(cancellationToken).ConfigureAwait(false);
                InterviewStatus = NodeInterviewStatus.Complete;
            },
            cancellationToken);
        }

        await interviewTask.ConfigureAwait(false);
    }

    internal void NotifyNodeInfoReceived(ApplicationUpdateRequest nodeInfoReceived)
    {
        // TODO: Log
        foreach (CommandClassInfo commandClassInfo in nodeInfoReceived.Generic.CommandClasses)
        {
            AddCommandClass(commandClassInfo);
        }

        _nodeInfoRecievedEvent.Set();
    }

    private void AddCommandClass(CommandClassInfo commandClassInfo)
    {
        lock(_commandClasses)
        {
            if (_commandClasses.TryGetValue(commandClassInfo.CommandClass, out CommandClass? existingCommandClass))
            {
                existingCommandClass.MergeInfo(commandClassInfo);
            }
            else
            {
                CommandClass commandClass = CommandClassFactory.Create(commandClassInfo, _driver, this);
                _commandClasses.Add(commandClassInfo.CommandClass, commandClass);
            }
        }
    }

    private async Task InterviewCommandClassesAsync(CancellationToken cancellationToken)
    {
        /*
            Command classes may depend on other command classes, so we need to interview them in topographical order.
            Instead of sorting them completely out of the gate, we'll just create a list of all the command classes (list A) and if its dependencies
            are met interview it and if not add to another list (list B). After exhausing the list A, swap list A and B and repeat until both are empty.
        */
        Queue<CommandClass> commandClasses = new(_commandClasses.Count);
        lock (_commandClasses)
        {
            foreach ((_, CommandClass commandClass) in _commandClasses)
            {
                commandClasses.Enqueue(commandClass);
            }
        }

        HashSet<CommandClassId> interviewedCommandClasses = new (_commandClasses.Count);
        Queue<CommandClass> blockedCommandClasses = new(_commandClasses.Count);
        while (commandClasses.Count > 0)
        {
            while (commandClasses.Count > 0)
            {
                CommandClass commandClass = commandClasses.Dequeue();
                CommandClassId commandClassId = commandClass.Info.CommandClass;

                bool isBlocked = false;
                CommandClassId[] commandClassDependencies = commandClass.Dependencies;
                for (int i = 0; i < commandClassDependencies.Length; i++)
                {
                    if (!interviewedCommandClasses.Contains(commandClassDependencies[i]))
                    {
                        isBlocked = true;
                        break;
                    }
                }

                if (isBlocked)
                {
                    blockedCommandClasses.Enqueue(commandClass);
                }
                else
                {
                    await commandClass.InterviewAsync(cancellationToken);
                    interviewedCommandClasses.Add(commandClassId);
                }
            }

            Queue<CommandClass> tmp = commandClasses;
            commandClasses = blockedCommandClasses;
            blockedCommandClasses = tmp;
        }
    }

    internal void ProcessCommand(CommandClassFrame frame)
    {
        CommandClass? commandClass;
        lock (_commandClasses)
        {
            if (!_commandClasses.TryGetValue(frame.CommandClassId, out commandClass))
            {
                // TODO: Log
                return;
            }
        }

        commandClass.ProcessCommand(frame);
    }
}
