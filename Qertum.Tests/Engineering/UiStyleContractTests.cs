using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Look rules the page markup relies on and bUnit cannot see, because bUnit does not apply CSS. Each one was a
/// visual regression found in review of the UI consolidation: Bootstrap's more specific rules beat a bare class.
/// </summary>
public sealed partial class UiStyleContractTests
{
    private static string AppCss => File.ReadAllText(Path.Combine(FindRepoRoot(), "Qertum.Web/wwwroot/app.css"));

    [Fact]
    public void ADisabledSoftDangerButtonKeepsItsRoseLook()
    {
        // .btn:disabled reads --bs-btn-disabled-* and wins over a plain class, so the button went transparent.
        var rule = Rule(@"\.btn-danger-soft:disabled");

        Assert.Contains("var(--accent-rose-glow)", rule, StringComparison.Ordinal);
        Assert.Contains("var(--accent-rose)", rule, StringComparison.Ordinal);
    }

    [Fact]
    public void ASmallSoftDangerButtonKeepsTheSmallPadding()
    {
        // Row buttons (btn-sm) were 4px 12px; the dialog's confirm button is the larger 6px 16px.
        Assert.Contains("padding: 4px 12px", Rule(@"\.btn-sm\.btn-danger-soft"), StringComparison.Ordinal);
    }

    [Fact]
    public void ATableCardKeepsItsSideSpacing()
    {
        // The card has no padding so the table runs edge to edge; without this the text sat 12px from the edge.
        Assert.Contains("padding-left: 20px", Rule(@"\.table-card \.table-dashboard (?:th|td):first-child(?:,\s*\.table-card \.table-dashboard (?:th|td):first-child)*"), StringComparison.Ordinal);
        Assert.Contains("padding-right: 20px", Rule(@"\.table-card \.table-dashboard (?:th|td):last-child(?:,\s*\.table-card \.table-dashboard (?:th|td):last-child)*"), StringComparison.Ordinal);
    }

    private static string Rule(string selectorPattern)
    {
        var match = Regex.Match(AppCss, @"(?m)^" + selectorPattern + @"\s*\{([^}]*)\}");
        Assert.True(match.Success, $"app.css has no rule for /{selectorPattern}/");
        return match.Groups[1].Value;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
