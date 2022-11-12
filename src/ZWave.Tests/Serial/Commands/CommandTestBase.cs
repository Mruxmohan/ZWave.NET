using System.Collections;
using System.Reflection;
using ZWave.Serial;
using ZWave.Serial.Commands;

namespace ZWave.Tests.Serial.Commands;

public class CommandTestBase
{
    private static readonly string[] ExcludedComparisonProperties = new[] { "Frame", "Data" };

    internal static void TestSendableCommand<TCommand>(
        DataFrameType dataFrameType,
        CommandId commandId,
        IReadOnlyList<(TCommand Command, byte[] ExpectedCommandParameters)> tests)
        where TCommand : struct, ICommand<TCommand>
    {
        Assert.AreEqual(dataFrameType, TCommand.Type);
        Assert.AreEqual(commandId, TCommand.CommandId);

        foreach ((TCommand command, byte[] expectedCommandParameters) in tests)
        {
            Assert.AreEqual(dataFrameType, command.Frame.Type);
            Assert.AreEqual(commandId, command.Frame.CommandId);
            Assert.That.MemoryIsEqual(expectedCommandParameters, command.Frame.CommandParameters);
        }
    }

    internal static void TestReceivableCommand<TCommand, TData>(
        DataFrameType dataFrameType,
        CommandId commandId,
        IReadOnlyList<(byte[] CommandParameters, TData ExpectedData)> tests)
        where TCommand : struct, ICommand<TCommand>
    {
        Assert.AreEqual(dataFrameType, TCommand.Type);

        if (commandId == 0)
        {
            Assert.ThrowsException<InvalidOperationException>(() => TCommand.CommandId);
        }
        else
        {
            Assert.AreEqual(commandId, TCommand.CommandId);
        }

        foreach ((ReadOnlyMemory<byte> commandParameters, TData expectedData) in tests)
        {
            var dataFrame = DataFrame.Create(dataFrameType, commandId, commandParameters.Span);
            var command = TCommand.Create(dataFrame);

            Assert.That.ObjectsAreEquivalent(expectedData, command, ExcludedComparisonProperties);
        }
    }
}
