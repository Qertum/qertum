using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Composite ML-DSA keys are not keys BouncyCastle's factories know. Every place that turns bytes
/// into a key, a key into bytes, or checks a signature against a key therefore goes through
/// <c>QertumKeyCodec</c>; a call site that reaches for BouncyCastle directly still works for RSA and
/// ECDSA and silently fails the first time it meets a composite key. This scan is what stops that.
/// </summary>
public sealed partial class KeyCodecUsageTests
{
    // The seam itself, and the composite implementation it dispatches to.
    private static readonly string[] AllowedPrefixes =
    [
        "Qertum.Services/Crypto/QertumKeyCodec.cs",
        "Qertum.Services/Crypto/Composite/",
    ];

    [Fact]
    public void NoProductionCodeBypassesTheKeyCodec()
    {
        var root = FindRepoRoot();
        var offenders = Directory.EnumerateDirectories(root, "Qertum.*")
            .Where(dir => !dir.EndsWith("Qertum.Tests", StringComparison.Ordinal))
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}"))
            .Select(f => Path.GetRelativePath(root, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(f => !AllowedPrefixes.Any(p => f.StartsWith(p, StringComparison.Ordinal)))
            .SelectMany(f => File.ReadLines(Path.Combine(root, f))
                .Select((line, i) => (File: f, Line: i + 1, Text: line))
                .Where(l => !l.Text.TrimStart().StartsWith("//", StringComparison.Ordinal)
                         && !l.Text.TrimStart().StartsWith("///", StringComparison.Ordinal))
                .Where(l => Bypass().IsMatch(l.Text)))
            .Select(l => $"{l.File}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0,
            "Parse, write and verify keys through QertumKeyCodec so composite ML-DSA keys work there too:\n"
            + string.Join('\n', offenders));
    }

    [GeneratedRegex(
        @"\bPublicKeyFactory\b|\bPrivateKeyFactory\b|\bPrivateKeyInfoFactory\b|\bSubjectPublicKeyInfoFactory\b"
        + @"|\bCreateSubjectKeyIdentifier\(|\bCreateAuthorityKeyIdentifier\(|\.SetPublicKey\(|\.Verify\(\)"
        + @"|\b(csr|cert|certificate|caCertificate|_caCertificate)!?\.GetPublicKey\(\)"
        // A namespace-qualified "new Org.BouncyCastle.OpenSsl.PemReader(" must match too.
        + @"|\bnew\s+(?:[\w.]+\.)?(?:PemReader|PemWriter|Asn1SignatureFactory|Asn1VerifierFactoryProvider)\("
        + @"|\bSignerUtilities\.GetSigner\(")]
    private static partial Regex Bypass();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
