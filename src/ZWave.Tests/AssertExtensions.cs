using System.Collections;
using System.Reflection;

namespace ZWave.Tests;

internal static class AssertExtensions
{
    public static void ConstructorValidatesNull<T>(this Assert _, params object[] parameters)
    {
        // Get the correct constructor. Note that we can't use the GetConstructor method since
        // out parameters are of some concrete types and the constructor may take a base class or interface.
        Type type = typeof(T);
        ConstructorInfo[] constructors = type.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        ConstructorInfo? matchingConstructor = null;
        foreach (ConstructorInfo constructor in constructors)
        {
            ParameterInfo[] constructorParameters = constructor.GetParameters();
            if (constructorParameters.Length != parameters.Length)
            {
                continue;
            }

            for (int i = 0; i < parameters.Length; i++)
            {
                var parameterType = parameters[i].GetType();
                if (!parameterType.IsInstanceOfType(constructorParameters[i].ParameterType))
                {
                    break;
                }
            }

            matchingConstructor = constructor;
        }

        Assert.IsNotNull(matchingConstructor, "Could not find constructor with the given parameter types.");

        // Sanity check the non-null case
        var constructedObject = matchingConstructor.Invoke(parameters);
        Assert.IsNotNull(constructedObject);
        Assert.IsInstanceOfType(constructedObject, type);

        // FOr each parameter, ensure it's null-checked
        for (int i = 0; i < parameters.Length; i++)
        {
            // Skip parameters which were given as null. This implies they're allowed to be null,
            // as proven by the successfully constructed object above.
            if (parameters[i] == null)
            {
                continue;
            }

            // Skip structs as they can't be null.
            if (!parameters[i].GetType().IsClass)
            {
                continue;
            }

            // Force the parameter in the i-th slot to be null
            var parametersCopy = (object[])parameters.Clone();
            parametersCopy[i] = null!;

            ParameterInfo parameterUnderTest = matchingConstructor.GetParameters()[i];
            try
            {
                matchingConstructor.Invoke(parametersCopy);

                // The construction should have failed.
                Assert.Fail($"The parameter `{parameterUnderTest.Name}` was not null-checked");
            }
            // When using ConstructorInfo.Invoke, the exception in wrapped in a TargetInvocationException
            catch (TargetInvocationException ex)
            {
                Assert.IsInstanceOfType(ex.InnerException, typeof(ArgumentNullException));

                string actualParamName = ((ArgumentNullException)ex.InnerException!).ParamName!;
                Assert.AreEqual(
                    parameterUnderTest.Name,
                    actualParamName,
                    "Parameter threw an ArgumentNullException with the wrong param name");
            }
        }
    }

    public static void ObjectsAreEquivalent(
        this Assert _,
        object? expectedObj,
        object? actualObj,
        IReadOnlyList<string>? excludedProperties = null)
        => ObjectsAreEquivalentInternal(expectedObj, actualObj, propertyPathBase: null, excludedProperties);

    public static void ObjectsAreEquivalentInternal(
        object? expectedObj,
        object? actualObj,
        string? propertyPathBase,
        IReadOnlyList<string>? excludedProperties = null)
    {
        if (expectedObj == null)
        {
            Assert.IsNull(actualObj);
            return;
        }

        Assert.IsNotNull(actualObj);

        excludedProperties ??= Array.Empty<string>();

        Type expectedType = expectedObj.GetType();
        Type actualType = actualObj.GetType();

        const BindingFlags bindingFlags = BindingFlags.Public | BindingFlags.Instance;
        PropertyInfo[] expectedProperties = expectedType.GetProperties(bindingFlags)
            .Where(p => !excludedProperties.Any(excludedProperty => p.Name.Equals(excludedProperty, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        PropertyInfo[] actualProperties = actualType.GetProperties(bindingFlags)
            .Where(p => !excludedProperties.Any(excludedProperty => p.Name.Equals(excludedProperty, StringComparison.OrdinalIgnoreCase)))
            .ToArray();
        Assert.AreEqual(expectedProperties.Length, actualProperties.Length, $"Object property counts do not match for object {propertyPathBase ?? "<root>"}");

        var properties = new List<(PropertyInfo ExpectedProperty, PropertyInfo ActualProperty)>(actualProperties.Length);
        foreach (PropertyInfo expectedProperty in expectedProperties)
        {
            PropertyInfo? actualProperty = actualProperties.FirstOrDefault(
                commandProperty => commandProperty.Name.Equals(expectedProperty.Name, StringComparison.Ordinal));

            Assert.IsNotNull(actualProperty, $"Could not find matching property: {GetPropertyPath(propertyPathBase, expectedProperty.Name)} ({expectedProperty.PropertyType.Name})");

            properties.Add((expectedProperty, actualProperty));
        }

        foreach ((PropertyInfo expectedProperty, PropertyInfo actualProperty) in properties)
        {
            object? expectedValue = expectedProperty.GetValue(expectedObj);
            object? actualValue = actualProperty.GetValue(actualObj);

            string propertyPath = GetPropertyPath(propertyPathBase, expectedProperty.Name);
            Type expectedPropertyType = expectedProperty.PropertyType;
            Type actualPropertyType = actualProperty.PropertyType;

            if (expectedPropertyType != actualPropertyType)
            {
                ObjectsAreEquivalentInternal(expectedValue, actualValue, propertyPath, excludedProperties);
            }
            else if (expectedPropertyType == typeof(ReadOnlyMemory<byte>))
            {
                Assert.That.MemoryIsEqual((ReadOnlyMemory<byte>)expectedValue!, (ReadOnlyMemory<byte>)actualValue!, $"Property '{propertyPath}' not equal");
            }
            else if (expectedPropertyType.IsGenericType && expectedPropertyType.GetGenericTypeDefinition() == typeof(ReadOnlyMemory<>))
            {
                Type[] genericArgs = expectedPropertyType.GetGenericArguments();

                MethodInfo memoryIsEqual = typeof(AssertExtensions).GetMethods(BindingFlags.Public | BindingFlags.Static)
                    .First(mi => mi.Name.Equals("MemoryIsEqual", StringComparison.OrdinalIgnoreCase) && mi.IsGenericMethodDefinition)
                    .MakeGenericMethod(genericArgs);

                memoryIsEqual.Invoke(null, new object?[] { Assert.That, expectedValue, actualValue, null });

            }
            else if (expectedPropertyType.IsGenericType && expectedPropertyType.GetGenericTypeDefinition() == typeof(HashSet<>))
            {
                Type[] genericArgs = expectedPropertyType.GetGenericArguments();
                Type listType = typeof(List<>).MakeGenericType(genericArgs);
                Type enumerableType = typeof(IEnumerable<>).MakeGenericType(genericArgs);
                ConstructorInfo listCtor = listType.GetConstructor(new[] { enumerableType })!;

                ICollection expectedValueList = (ICollection)listCtor.Invoke(new[] { expectedValue });
                ICollection actualValueList = (ICollection)listCtor.Invoke(new[] { actualValue });

                CollectionAssert.AreEquivalent(expectedValueList, actualValueList, $"Property '{propertyPath}' not equal");
            }
            else if (expectedPropertyType.IsGenericType && expectedPropertyType.GetGenericTypeDefinition() == typeof(IReadOnlyList<>))
            {
                Type[] genericArgs = expectedPropertyType.GetGenericArguments();
                Type listType = typeof(List<>).MakeGenericType(genericArgs);
                Type enumerableType = typeof(IEnumerable<>).MakeGenericType(genericArgs);
                ConstructorInfo listCtor = listType.GetConstructor(new[] { enumerableType })!;

                ICollection expectedValueList = (ICollection)listCtor.Invoke(new[] { expectedValue });
                ICollection actualValueList = (ICollection)listCtor.Invoke(new[] { actualValue });

                MethodInfo stringJoin = typeof(string).GetMethods(BindingFlags.Public | BindingFlags.Static)
                    .First(mi => mi.Name.Equals("Join", StringComparison.OrdinalIgnoreCase)
                        && mi.GetParameters().Length == 2
                        && mi.GetParameters()[0].ParameterType == typeof(string)
                        && mi.IsGenericMethodDefinition)
                    .MakeGenericMethod(genericArgs);

                CollectionAssert.AreEqual(
                    expectedValueList,
                    actualValueList,
                    $"Property '{propertyPath}' not equal.{Environment.NewLine}"
                        + $"  Expected: {stringJoin.Invoke(null, new object[] { ", ", expectedValueList })}{Environment.NewLine}"
                        + $"  Actual:   {stringJoin.Invoke(null, new object[] { ", ", actualValueList })}{Environment.NewLine}");
            }
            else
            {
                Assert.AreEqual(expectedValue, actualValue, $"Property '{propertyPath}' not equal");
            }
        }

        static string GetPropertyPath(string? propertyPathBase, string propertyName)
            => propertyPathBase == null
                ? propertyName
                : propertyPathBase + "." + propertyName;
    }

    public static void MemoryIsEqual(this Assert _, ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> actual, string? message = null)
        => Assert.IsTrue(
            expected.Span.SequenceEqual(actual.Span),
            $"{(message != null ? message + ". " : string.Empty)}Sequences are not equal!{Environment.NewLine}"
                + $"  Expected: 0x{Convert.ToHexString(expected.Span)}{Environment.NewLine}"
                + $"  Actual:   0x{Convert.ToHexString(actual.Span)}{Environment.NewLine}");

    public static void MemoryIsEqual<T>(this Assert _, ReadOnlyMemory<T> expected, ReadOnlyMemory<T> actual, string? message = null)
        => Assert.IsTrue(
            expected.Span.SequenceEqual(actual.Span),
            $"{(message != null ? message + ". " : string.Empty)}Sequences are not equal!{Environment.NewLine}"
                + $"  Expected: {string.Join(", ", expected.ToArray())}{Environment.NewLine}"
                + $"  Actual:   {string.Join(", ", actual.ToArray())}{Environment.NewLine}");
}
