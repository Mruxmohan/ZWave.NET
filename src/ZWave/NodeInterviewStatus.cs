namespace ZWave;

public enum NodeInterviewStatus
{
    /// <summary>
    /// The node has not been interviewed.
    /// </summary>
    None,

    /// <summary>
    /// The node's protocol information has been queried from the controller.
    /// </summary>
    ProtocolInfo,

    /// <summary>
    /// The node's base information has been queried from the controller, eg the list of supported command classes.
    /// </summary>
    NodeInfo,

    /// <summary>
    /// The node has been fully interviewed.
    /// </summary>
    Complete,
}
