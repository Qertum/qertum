using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Every header and card in Qertum.Web and Qertum.IdentityService shows the qertum.com lockup: the mark,
/// the name "Qertum" and the tagline "Post-Quantum Security", styled once by DesignSystem's brand.css.
/// The product used to show a padlock tile and per-host subtitles, which looked like another brand.
/// </summary>
public sealed partial class BrandLockupTests
{
    private static readonly string[] Projects = ["Qertum.Web", "Qertum.IdentityService"];

    [Fact]
    public void EveryBrandNameIsTheSiteLockup()
    {
        var root = FindRepoRoot();
        var sources = Projects.SelectMany(p => Directory.EnumerateFiles(Path.Combine(root, p), "*", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cshtml", StringComparison.Ordinal)
                || f.EndsWith(".cs", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(f => (File: Path.GetRelativePath(root, f), Text: File.ReadAllText(f)))
            .Where(s => s.Text.Contains("class=\"brand-name\"", StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(sources);
        var offenders = sources.Where(s =>
                BrandName().Matches(s.Text).Count != Lockup().Matches(s.Text).Count
                || BrandName().Matches(s.Text).Count != s.Text.Split("class=\"brand-mark\"").Length - 1)
            .Select(s => s.File)
            .ToList();
        Assert.True(offenders.Count == 0, $"Brand lockup differs from qertum.com in: {string.Join(", ", offenders)}");
    }

    [Fact]
    public void TheTokensImportTheBrandLockup()
    {
        var root = FindRepoRoot();
        Assert.Contains("@import url('brand.css');",
            File.ReadAllText(Path.Combine(root, "Qertum.DesignSystem/wwwroot/tokens.css")), StringComparison.Ordinal);
        Assert.Contains("url('brand/qertum-mark.svg')",
            File.ReadAllText(Path.Combine(root, "Qertum.DesignSystem/wwwroot/brand.css")), StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(root, "Qertum.DesignSystem/wwwroot/brand/favicon.svg")));
        Assert.True(File.Exists(Path.Combine(root, "Qertum.DesignSystem/wwwroot/brand/favicon.ico")));
    }

    /// <summary>
    /// Every page head carries the site's two icons, like qertum.com: the SVG, and the 32x32 <c>favicon.ico</c>
    /// for browsers that do not use an SVG icon (the product showed none there after the PNG was removed).
    /// </summary>
    [Fact]
    public void EveryPageHeadLinksBothFavicons()
    {
        var root = FindRepoRoot();
        var heads = Projects.SelectMany(p => Directory.EnumerateFiles(Path.Combine(root, p), "*", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".razor", StringComparison.Ordinal) || f.EndsWith(".cshtml", StringComparison.Ordinal)
                || f.EndsWith(".cs", StringComparison.Ordinal))
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Select(f => (File: Path.GetRelativePath(root, f), Text: File.ReadAllText(f)))
            .Where(s => s.Text.Contains("<head>", StringComparison.Ordinal))
            .ToList();

        Assert.NotEmpty(heads);
        var offenders = heads.Where(s =>
                s.Text.Split("<head>").Length - 1 != s.Text.Split("brand/favicon.svg").Length - 1
                || s.Text.Split("<head>").Length - 1 != s.Text.Split("brand/favicon.ico").Length - 1)
            .Select(s => s.File)
            .ToList();
        Assert.True(offenders.Count == 0, $"A page head lacks one of the two favicons in: {string.Join(", ", offenders)}");
    }

    [Theory]
    [InlineData("Qertum.Web")]
    [InlineData("Qertum.IdentityService")]
    public void TheHostServesTheBrandAssets(string project)
    {
        var manifest = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, $"{project}.staticwebassets.endpoints.json"))
            .Replace(" ", "", StringComparison.Ordinal);
        foreach (var route in new[] { "brand.css", "brand/qertum-mark.svg", "brand/favicon.svg", "brand/favicon.ico" })
            Assert.Contains($"\"Route\":\"_content/Qertum.DesignSystem/{route}\"", manifest, StringComparison.Ordinal);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }

    [GeneratedRegex(@"class=""brand-name""")]
    private static partial Regex BrandName();

    [GeneratedRegex(@"<span class=""brand-name"">Qertum</span>\s*<span class=""brand-tagline"">Post-Quantum Security</span>")]
    private static partial Regex Lockup();
}
