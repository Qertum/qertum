using System.Text.Json;

namespace Qertum.Services.Acme;

/// <summary>
/// Reads JSON an ACME client sent. A wrong shape is the client's error, so every reader here throws
/// <see cref="AcmeException"/> <c>malformed</c> (400). <see cref="JsonElement"/>'s own accessors throw
/// <see cref="KeyNotFoundException"/> or <see cref="InvalidOperationException"/> instead, which
/// <c>HandleAcme</c> can only answer as a <c>serverInternal</c> 500 logged at error level.
/// </summary>
internal static class AcmeJson
{
    /// <summary>Parses <paramref name="json"/>, which must be a JSON object.</summary>
    public static JsonDocument ParseObject(string json, string what) =>
        RequireObjectRoot(() => JsonDocument.Parse(json), what);

    /// <summary>Parses UTF-8 <paramref name="utf8"/>, which must be a JSON object.</summary>
    public static JsonDocument ParseObject(ReadOnlyMemory<byte> utf8, string what) =>
        RequireObjectRoot(() => JsonDocument.Parse(utf8), what);

    /// <summary>The string member <paramref name="name"/>; absent, null or not a string is malformed.</summary>
    public static string RequiredString(JsonElement obj, string name, string what) =>
        OptionalString(obj, name, what) ?? throw Malformed($"The {what} is missing '{name}'.");

    /// <summary>The string member <paramref name="name"/>, or null when absent or null.</summary>
    public static string? OptionalString(JsonElement obj, string name, string what) =>
        Member(obj, name, what) switch
        {
            null => null,
            { ValueKind: JsonValueKind.String } value => value.GetString(),
            _ => throw Malformed($"'{name}' in the {what} must be a string.")
        };

    /// <summary>The boolean member <paramref name="name"/>, or false when absent or null.</summary>
    public static bool OptionalBool(JsonElement obj, string name, string what) =>
        Member(obj, name, what) switch
        {
            null => false,
            { ValueKind: JsonValueKind.True } => true,
            { ValueKind: JsonValueKind.False } => false,
            _ => throw Malformed($"'{name}' in the {what} must be true or false.")
        };

    /// <summary>The array member <paramref name="name"/>; absent or not an array is malformed.</summary>
    public static JsonElement RequiredArray(JsonElement obj, string name, string what) =>
        Member(obj, name, what) is { ValueKind: JsonValueKind.Array } value
            ? value
            : throw Malformed($"The {what} must carry '{name}' as an array.");

    private static JsonElement? Member(JsonElement obj, string name, string what)
    {
        if (obj.ValueKind != JsonValueKind.Object)
            throw Malformed($"The {what} must be a JSON object.");
        return obj.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value : null;
    }

    private static JsonDocument RequireObjectRoot(Func<JsonDocument> parse, string what)
    {
        JsonDocument doc;
        try
        {
            doc = parse();
        }
        catch (JsonException)
        {
            throw Malformed($"The {what} is not valid JSON.");
        }

        if (doc.RootElement.ValueKind == JsonValueKind.Object)
            return doc;
        doc.Dispose();
        throw Malformed($"The {what} must be a JSON object.");
    }

    private static AcmeException Malformed(string detail) => new("malformed", detail);
}
