using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Time is read through <see cref="TimeProvider"/>, so expiry, retry and retention logic can be tested
/// with a fake clock instead of by waiting. Services take it by injection (optionally, where tests build
/// them directly); composition roots with no service provider yet read <c>TimeProvider.System</c>.
/// </summary>
public sealed partial class ClockUsageTests
{
    // Entity property defaults (CreatedAtUtc = DateTime.UtcNow and the like): entities take no
    // services, and the pipeline overwrites these values on the paths that matter.
    private static readonly HashSet<string> EntityDefaults = new(StringComparer.Ordinal)
    {
        "Qertum.Contracts/CertificateRequest.cs",
        "Qertum.Contracts/CertificateTemplate.cs",
        "Qertum.Contracts/IssuancePolicy.cs",
        "Qertum.Contracts/IssuancePolicyVersion.cs",
        "Qertum.Services/Acme/AcmeAccount.cs",
        "Qertum.Services/Acme/AcmeExternalAccountKey.cs",
        "Qertum.Services/Acme/AcmeOrder.cs",
        "Qertum.Services/Est/EstEnrollmentCredential.cs",
    };

    [Fact]
    public void NoCodeReadsTheSystemClockDirectly()
    {
        var root = FindRepoRoot();
        var offenders = Directory.EnumerateDirectories(root, "Qertum.*")
            .Where(dir => !dir.EndsWith("Qertum.Tests", StringComparison.Ordinal))
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                     && !f.Contains($"{Path.DirectorySeparatorChar}Migrations{Path.DirectorySeparatorChar}"))
            .Select(f => Path.GetRelativePath(root, f).Replace(Path.DirectorySeparatorChar, '/'))
            .Where(f => !EntityDefaults.Contains(f))
            .SelectMany(f => File.ReadLines(Path.Combine(root, f))
                .Select((line, i) => (File: f, Line: i + 1, Text: line))
                .Where(l => DirectClockRead().IsMatch(l.Text)))
            .Select(l => $"{l.File}:{l.Line}: {l.Text.Trim()}")
            .ToList();

        Assert.True(offenders.Count == 0,
            "Read time through an injected TimeProvider (or TimeProvider.System at a composition root):\n"
            + string.Join('\n', offenders));
    }

    [GeneratedRegex(@"\bDateTime(Offset)?\.(UtcNow|Now)\b")]
    private static partial Regex DirectClockRead();

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
