using Microsoft.Extensions.Logging;
using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave;

internal static partial class Logging
{
    /* SerialApi: 100-199 */

    [LoggerMessage(
        EventId = 100,
        Level = LogLevel.Trace,
        Message = "ZWave Serial port `{portName}` opened")]
    public static partial void LogSerialApiPortOpened(this ILogger logger, string portName);

    [LoggerMessage(
        EventId = 101,
        Level = LogLevel.Trace,
        Message = "ZWave Serial port `{portName}` closed")]
    public static partial void LogSerialApiPortClosed(this ILogger logger, string portName);

    [LoggerMessage(
        EventId = 102,
        Level = LogLevel.Trace,
        Message = "ZWave Serial port `{portName}` re-opened")]
    public static partial void LogSerialApiPortReopened(this ILogger logger, string portName);

    [LoggerMessage(
        EventId = 103,
        Level = LogLevel.Trace,
        Message = "Skipped {numBytes} bytes of invalid data from the Serial port")]
    public static partial void LogSerialApiSkippedBytes(this ILogger logger, long numBytes);

    [LoggerMessage(
        EventId = 104,
        Level = LogLevel.Trace,
        Message = "Received Serial API frame: {frame}")]
    public static partial void LogSerialApiFrameReceived(this ILogger logger, Frame frame);

    [LoggerMessage(
        EventId = 105,
        Level = LogLevel.Trace,
        Message = "Received Serial API data frame: {frame}")]
    public static partial void LogSerialApiDataFrameReceived(this ILogger logger, DataFrame frame);

    [LoggerMessage(
        EventId = 106,
        Level = LogLevel.Trace,
        Message = "Received invalid Serial API data frame: {frame}")]
    public static partial void LogSerialApiInvalidDataFrameReceived(this ILogger logger, DataFrame frame);

    [LoggerMessage(
        EventId = 107,
        Level = LogLevel.Trace,
        Message = "Sent Serial API frame: {frame}")]
    public static partial void LogSerialApiFrameSent(this ILogger logger, Frame frame);

    [LoggerMessage(
        EventId = 108,
        Level = LogLevel.Trace,
        Message = "Sent Serial API data frame: {frame}")]
    public static partial void LogSerialApiDataFrameSent(this ILogger logger, DataFrame frame);

    [LoggerMessage(
        EventId = 109,
        Level = LogLevel.Trace,
        Message = "Received frame transmission reply unexpectedly: {frame}")]
    public static partial void LogSerialApiUnexpectedFrame(this ILogger logger, Frame frame);

    [LoggerMessage(
        EventId = 110,
        Level = LogLevel.Trace,
        Message = "Received Serial API frame with unknown type `{frameType}`")]
    public static partial void LogSerialApiFrameUnknownType(this ILogger logger, FrameType frameType);

    [LoggerMessage(
        EventId = 111,
        Level = LogLevel.Trace,
        Message = "Received Serial API data frame with unknown type `{dataFrameType}`")]
    public static partial void LogSerialApiDataFrameUnknownType(this ILogger logger, DataFrameType dataFrameType);

    [LoggerMessage(
        EventId = 112,
        Level = LogLevel.Trace,
        Message = "Serial API read was cancelled")]
    public static partial void LogSerialApiReadCancellation(this ILogger logger);

    [LoggerMessage(
        EventId = 113,
        Level = LogLevel.Warning,
        Message = "Serial API read exception")]
    public static partial void LogSerialApiReadException(this ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 114,
        Level = LogLevel.Warning,
        Message = "Serial API write exception")]
    public static partial void LogSerialApiWriteException(this ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 115,
        Level = LogLevel.Warning,
        Message = "Serial API frame transmission did not receive an ACK before the timeout period")]
    public static partial void LogSerialApiFrameDeliveryAckTimeout(this ILogger logger);

    [LoggerMessage(
        EventId = 116,
        Level = LogLevel.Warning,
        Message = "Serial API frame transmission failed (attempt #{attempt})")]
    public static partial void LogSerialApiFrameTransmissionRetry(this ILogger logger, int attempt);

    /* Driver: 200-299 */

    [LoggerMessage(
        EventId = 200,
        Level = LogLevel.Information,
        Message = "Driver initialization sequence starting")]
    public static partial void LogDriverInitializing(this ILogger logger);

    [LoggerMessage(
        EventId = 201,
        Level = LogLevel.Information,
        Message = "Performing soft reset")]
    public static partial void LogSoftReset(this ILogger logger);

    [LoggerMessage(
        EventId = 202,
        Level = LogLevel.Information,
        Message = "Driver initialization sequence complete")]
    public static partial void LogDriverInitialized(this ILogger logger);

    [LoggerMessage(
        EventId = 203,
        Level = LogLevel.Debug,
        Message = "Identifying controller")]
    public static partial void LogControllerIdentifying(this ILogger logger);

    [LoggerMessage(
        EventId = 204,
        Level = LogLevel.Information,
        Message = "Controller identity:\n" +
        "Home ID = {homeId}\n" +
        "Node ID = {nodeId}")]
    public static partial void LogControllerIdentity(this ILogger logger, uint homeId, byte nodeId);

    [LoggerMessage(
        EventId = 205,
        Level = LogLevel.Information,
        Message = "Serial API capabilities:\n" +
        "Serial API Version = {serialApiVersion}\n" +
        "Manufacturer ID = {manufacturerId}\n" +
        "Product type = {productType}\n" +
        "Product ID = {productId}\n" +
        "Supported Commands = {supportedCommands}")]
    public static partial void LogSerialApiCapabilities(
        this ILogger logger,
        Version serialApiVersion,
        ushort manufacturerId,
        ushort productType,
        ushort productId,
        string supportedCommands);

    [LoggerMessage(
        EventId = 206,
        Level = LogLevel.Information,
        Message = "Controller library:\n" +
        "Library version = {libraryVersion}\n" +
        "Library type = {libraryType}")]
    public static partial void LogControllerLibraryVersion(this ILogger logger, string libraryVersion, LibraryType libraryType);

    [LoggerMessage(
        EventId = 207,
        Level = LogLevel.Information,
        Message = "Controller capabilities: {controllerCapabilities}")]
    public static partial void LogControllerCapabilities(this ILogger logger, ControllerCapabilities controllerCapabilities);

    [LoggerMessage(
        EventId = 208,
        Level = LogLevel.Information,
        Message = "Supported Serial API Setup subcommands: {supportedSubcommands}")]
    public static partial void LogControllerSupportedSerialApiSetupSubcommands(this ILogger logger, string supportedSubcommands);

    [LoggerMessage(
        EventId = 209,
        Level = LogLevel.Debug,
        Message = "Enabling TX status report success: {success}")]
    public static partial void LogEnableTxStatusReport(this ILogger logger, bool success);

    [LoggerMessage(
        EventId = 210,
        Level = LogLevel.Debug,
        Message = "SUC Node Id: {sucNodeId}")]
    public static partial void LogControllerSucNodeId(this ILogger logger, byte sucNodeId);

    [LoggerMessage(
        EventId = 211,
        Level = LogLevel.Information,
        Message = "Init data:\n" +
        "API Version = {apiVersion}\n" +
        "API Capabilities = {apiCapabilities}\n" +
        "Chip type = {chipType}\n" +
        "Chip version = {chipVersion}\n" +
        "Node IDs = {nodeIds}")]
    public static partial void LogInitData(
        this ILogger logger,
        byte apiVersion,
        GetInitDataCapabilities apiCapabilities,
        byte chipType,
        byte chipVersion,
        string nodeIds);

    [LoggerMessage(
        EventId = 212,
        Level = LogLevel.Error,
        Message = "Data frame processing exception")]
    public static partial void LogDataFrameProcessingException(this ILogger logger, Exception exception);

    [LoggerMessage(
        EventId = 213,
        Level = LogLevel.Warning,
        Message = "Unexpected SerialApiStarted command")]
        public static partial void LogUnexpectedSerialApiStarted(this ILogger logger);

    [LoggerMessage(
        EventId = 214,
        Level = LogLevel.Warning,
        Message = "Unsolicited request for unknown node id {nodeId}")]
    public static partial void LogUnknownNodeId(this ILogger logger, int nodeId);

    [LoggerMessage(
        EventId = 215,
        Level = LogLevel.Warning,
        Message = "Unexpected response frame: {frame}")]
    public static partial void LogUnexpectedResponseFrame(this ILogger logger, DataFrame frame);

    [LoggerMessage(
        EventId = 216,
        Level = LogLevel.Warning,
        Message = "Unexpected command id in response frame. Expected command id: {expectedCommandId}. Recieved frame: {frame}")]
    public static partial void LogUnexpectedCommandIdResponseFrame(this ILogger logger, CommandId expectedCommandId, DataFrame frame);
}
