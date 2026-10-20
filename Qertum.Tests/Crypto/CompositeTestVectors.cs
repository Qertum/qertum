using System.Text.Json;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// The composite ML-DSA test vectors published with the draft. They are the only independent oracle
/// for the encoding and the signing procedure, so every composite test that can use them does.
/// </summary>
internal static class CompositeTestVectors
{
    public const string DraftRevision = "draft-ietf-lamps-pq-composite-sigs-19";

    public const string Source =
        "https://github.com/lamps-wg/draft-composite-sigs/blob/f0627ab34acfe1aee0abce4bee91ed2b577eab76/src/testvectors.json";

    public sealed record Vector(
        string TcId,
        byte[] PublicKey,
        byte[] Certificate,
        byte[] PrivateKey,
        byte[] PrivateKeyPkcs8,
        byte[] Signature,
        byte[] SignatureWithContext);

    private static readonly Lazy<(byte[] Message, byte[] Context, IReadOnlyDictionary<string, Vector> Tests)> Loaded =
        new(Load);

    /// <summary>The message every vector signs.</summary>
    public static byte[] Message => Loaded.Value.Message;

    /// <summary>The context string <c>sWithContext</c> was produced under.</summary>
    public static byte[] Context => Loaded.Value.Context;

    public static IReadOnlyDictionary<string, Vector> ByTcId => Loaded.Value.Tests;

    public static Vector For(CompositeAlgorithm algorithm) => ByTcId["id-" + algorithm.Name];

    public static TheoryData<string> AlgorithmNames => [.. CompositeAlgorithms.All.Select(a => a.Name)];

    private static (byte[], byte[], IReadOnlyDictionary<string, Vector>) Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Crypto", "TestData", "composite-sigs-testvectors.json");
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        var root = document.RootElement;
        static byte[] Bytes(JsonElement element, string name) => Convert.FromBase64String(element.GetProperty(name).GetString()!);

        var tests = root.GetProperty("tests").EnumerateArray()
            .Select(t => new Vector(
                t.GetProperty("tcId").GetString()!,
                Bytes(t, "pk"), Bytes(t, "x5c"), Bytes(t, "sk"), Bytes(t, "sk_pkcs8"),
                Bytes(t, "s"), Bytes(t, "sWithContext")))
            .ToDictionary(v => v.TcId, StringComparer.Ordinal);

        return (Bytes(root, "m"), Bytes(root, "ctx"), tests);
    }
}
