﻿using Microsoft.Extensions.Logging;
using ZWave.CommandClasses;
using ZWave.Serial.Commands;

namespace ZWave;

public sealed class Node
{
    private readonly Driver _driver;

    private readonly ILogger _logger;

    private readonly AsyncAutoResetEvent _nodeInfoRecievedEvent = new AsyncAutoResetEvent();

    private readonly Dictionary<CommandClassId, CommandClass> _commandClasses = new Dictionary<CommandClassId, CommandClass>();

    private Task? _interviewTask;

    private CancellationTokenSource? _interviewCancellationTokenSource;

    internal Node(byte id, Driver driver, ILogger logger)
    {
        Id = id;
        _driver = driver ?? throw new ArgumentNullException(nameof(driver));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public byte Id { get; }

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
    {
        CommandClassId commandClassId = CommandClassFactory.GetCommandClassId<TCommandClass>();
        return (TCommandClass)GetCommandClass(commandClassId);
    }

    public CommandClass GetCommandClass(CommandClassId commandClassId)
    {
        CommandClass? commandClass;
        lock (_commandClasses)
        {
            if (!_commandClasses.TryGetValue(commandClassId, out commandClass))
            {
                throw new ZWaveException(ZWaveErrorCode.CommandClassNotImplemented, $"The command class {commandClassId} is not implemented by this node.");
            }
        }

        return commandClass;
    }

    /// <summary>
    /// Interviews a node.
    /// </summary>
    /// <remarks>
    /// the interview may take a very long time, so the returned task should generally not be awaited.
    /// </remarks>
    internal async Task InterviewAsync(CancellationToken cancellationToken)
    {
        // Cancel any previous interview
        if (_interviewCancellationTokenSource != null)
        {
            _interviewCancellationTokenSource.Cancel();
        }

        // Wait for any previous interview to stop
        if (_interviewTask != null)
        {
            await _interviewTask;
        }

        _interviewCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _interviewTask = Task.Run(async () =>
        {
            try
            {
                CancellationToken cancellationToken = _interviewCancellationTokenSource.Token;

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

                // This is all we need for the controller node
                if (Id == _driver.Controller.NodeId)
                {
                    return;
                }

                // This request causes unsolicited requests from the controller (kind of like a callback)
                // with command id ApplicationControllerUpdate
                var requestNodeInfoRequest = RequestNodeInfoRequest.Create(Id);
                ResponseStatusResponse response = await _driver.SendCommandAsync<RequestNodeInfoRequest, ResponseStatusResponse>(requestNodeInfoRequest, cancellationToken)
                    .ConfigureAwait(false);
                if (!response.WasRequestAccepted)
                {
                    // TODO: Log
                    // TODO: Retry
                    return;
                }

                await _nodeInfoRecievedEvent.WaitAsync().WaitAsync(cancellationToken).ConfigureAwait(false);

                // Initialize command classes
                List<Task> commandClassInitializationTasks;
                lock (_commandClasses)
                {
                    commandClassInitializationTasks = new List<Task>(_commandClasses.Count);
                    foreach (KeyValuePair<CommandClassId, CommandClass> pair in _commandClasses)
                    {
                        CommandClass commandClass = pair.Value;
                        Task initializationTask = commandClass.InterviewAsync(cancellationToken);
                        commandClassInitializationTasks.Add(initializationTask);
                    }
                }

                await Task.WhenAll(commandClassInitializationTasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        },
        cancellationToken);
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
