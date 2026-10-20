using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Qertum.Web and Qertum.IdentityService share one set of design tokens from Qertum.DesignSystem
/// instead of hand-mirroring them. These tests fail if either stylesheet stops importing the shared
/// file, starts declaring a shared token again (the drift the library exists to end), uses a token
/// nobody declares, or if either host stops serving the file at the path the import names.
/// </summary>
public sealed partial class DesignTokensTests
{
    private const string TokensRoute = "_content/Qertum.DesignSystem/tokens.css";

    public static TheoryData<string> Stylesheets =>
    [
        "Qertum.Web/wwwroot/app.css",
        "Qertum.IdentityService/wwwroot/identity.css",
    ];

    [Theory]
    [MemberData(nameof(Stylesheets))]
    public void TheStylesheetImportsTheSharedTokens(string stylesheet) =>
        Assert.Contains($"@import url('{TokensRoute}');", Read(stylesheet), StringComparison.Ordinal);

    [Theory]
    [MemberData(nameof(Stylesheets))]
    public void TheStylesheetDeclaresNoSharedToken(string stylesheet)
    {
        var shared = Declared(Read("Qertum.DesignSystem/wwwroot/tokens.css"));

        var redeclared = Declared(Read(stylesheet)).Intersect(shared).Order().ToList();

        Assert.Empty(redeclared);
    }

    [Theory]
    [MemberData(nameof(Stylesheets))]
    public void EveryTokenTheStylesheetUsesIsDeclared(string stylesheet)
    {
        var css = Read(stylesheet);
        var declared = Declared(Read("Qertum.DesignSystem/wwwroot/tokens.css")).Union(Declared(css)).ToHashSet();

        var undeclared = UsedToken().Matches(css).Select(m => m.Groups[1].Value)
            .Where(t => !declared.Contains(t)).Distinct().Order().ToList();

        Assert.Empty(undeclared);
    }

    [Theory]
    [InlineData("Qertum.Web")]
    [InlineData("Qertum.IdentityService")]
    public void TheHostServesTheTokensAtTheImportedPath(string project)
    {
        // The static web assets manifest is what MapStaticAssets serves from; the unfingerprinted
        // route must be there because a relative @import cannot name the fingerprinted one.
        var manifest = Path.Combine(AppContext.BaseDirectory, $"{project}.staticwebassets.endpoints.json");

        Assert.Contains($"\"Route\":\"{TokensRoute}\"", File.ReadAllText(manifest).Replace(" ", "", StringComparison.Ordinal),
            StringComparison.Ordinal);
    }

    // The design system is flat: no gradients in either UI. Vendored libraries under wwwroot/lib are
    // not ours to restyle and are skipped.
    [Theory]
    [InlineData("Qertum.Web")]
    [InlineData("Qertum.IdentityService")]
    [InlineData("Qertum.DesignSystem")]
    public void NoUiSourceUsesAGradient(string project)
    {
        var root = Path.Combine(FindRepoRoot(), project);
        var offenders = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".css", StringComparison.Ordinal) || f.EndsWith(".razor", StringComparison.Ordinal)
                || f.EndsWith(".cshtml", StringComparison.Ordinal) || f.EndsWith(".cs", StringComparison.Ordinal))
            .Where(f => !IsExcluded(Path.GetRelativePath(root, f)))
            .Where(f => Gradient().IsMatch(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(root, f))
            .ToList();

        Assert.True(offenders.Count == 0, $"Gradients in {project}: {string.Join(", ", offenders)}");
    }

    private static bool IsExcluded(string relativePath)
    {
        var parts = relativePath.Split(Path.DirectorySeparatorChar);
        return parts[0] is "bin" or "obj" || (parts.Length > 1 && parts[0] == "wwwroot" && parts[1] == "lib");
    }

    private static HashSet<string> Declared(string css) =>
        DeclaredToken().Matches(css).Select(m => m.Groups[1].Value).ToHashSet();

    // Bootstrap's .text-muted is a dark grey meant for light pages; on the dark theme it made
    // secondary text (e.g. role descriptions on /roles) nearly invisible.
    [Fact]
    public void BootstrapMutedText_UsesTheDarkThemeMutedToken()
    {
        var css = Read("Qertum.Web/wwwroot/app.css");
        Assert.Matches(new System.Text.RegularExpressions.Regex(@"(?m)^\.text-muted\s*\{[^}]*color:\s*var\(--text-muted\)\s*!important"), css);
    }

    // Components (.razor and scoped .razor.css) used to be invisible to the token check, which is how
    // --accent, --surface and --bg-input shipped undeclared: the rule using them silently did nothing.
    // A token counts as declared when tokens.css, app.css or any component source sets it (a component may
    // set its own through an inline custom property, as the audit chips do). --bs-* are Bootstrap's own.
    [Fact]
    public void EveryTokenUsedByAComponentIsDeclared()
    {
        var root = Path.Combine(FindRepoRoot(), "Qertum.Web");
        var sep = Path.DirectorySeparatorChar;
        var sources = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => (f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".razor.css", StringComparison.Ordinal))
                        && !f.Contains($"{sep}bin{sep}", StringComparison.Ordinal)
                        && !f.Contains($"{sep}obj{sep}", StringComparison.Ordinal))
            .ToDictionary(f => f, File.ReadAllText);

        var declared = Declared(Read("Qertum.DesignSystem/wwwroot/tokens.css"))
            .Union(Declared(Read("Qertum.Web/wwwroot/app.css")))
            .Union(sources.Values.SelectMany(Declared))
            .ToHashSet();

        var undeclared = sources
            .SelectMany(pair => UsedToken().Matches(pair.Value).Select(m => (File: Path.GetRelativePath(root, pair.Key), Token: m.Groups[1].Value)))
            .Where(use => !declared.Contains(use.Token) && !use.Token.StartsWith("--bs-", StringComparison.Ordinal))
            .Select(use => $"{use.File}: {use.Token}")
            .Distinct().Order().ToList();

        Assert.Empty(undeclared);
    }

    private static string Read(string relativePath) => File.ReadAllText(Path.Combine(FindRepoRoot(), relativePath));

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }

    [GeneratedRegex(@"(linear|radial|conic)-gradient\(")]
    private static partial Regex Gradient();

    [GeneratedRegex(@"(--[\w-]+)\s*:")]
    private static partial Regex DeclaredToken();

    [GeneratedRegex(@"var\((--[\w-]+)")]
    private static partial Regex UsedToken();
}
