using System.Text.RegularExpressions;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Looks stay in stylesheets. An inline style that sets colour, background, border, padding, margin or font
/// is how the old pages ended up with 289 inline styles and the same table header style pasted 13 times.
/// New look goes in a class in app.css or the page's scoped .razor.css. Layout (display, grid, position,
/// width, gap, cursor) and a component's own custom properties may stay inline. A genuinely dynamic look may
/// be listed below; the list may only shrink: an entry that no longer matches a file fails the test.
/// </summary>
public sealed partial class InlineStyleTests
{
    // "relative path|property: value", exactly as found. Add nothing without a reason a class cannot cover.
    private static readonly HashSet<string> AllowList = new(StringComparer.Ordinal);

    [Fact]
    public void NoInlineStyleSetsALookOutsideTheAllowList()
    {
        var found = Offenders().ToHashSet(StringComparer.Ordinal);

        var added = found.Except(AllowList).Order().ToList();
        var stale = AllowList.Except(found).Order().ToList();

        Assert.True(added.Count == 0, "Inline look found; use a class (app.css or scoped .razor.css):\n" + string.Join("\n", added));
        Assert.True(stale.Count == 0, "Allow-list entries that no longer match anything; delete them:\n" + string.Join("\n", stale));
    }

    private static IEnumerable<string> Offenders()
    {
        var root = Path.Combine(FindRepoRoot(), "Qertum.Web");
        foreach (var file in Directory.EnumerateFiles(Path.Combine(root, "Components"), "*.razor", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            foreach (Match style in InlineStyle().Matches(File.ReadAllText(file)))
            {
                foreach (var declaration in style.Groups[1].Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var colon = declaration.IndexOf(':');
                    if (colon < 0) continue;
                    var property = declaration[..colon].Trim();
                    if (property.StartsWith("--", StringComparison.Ordinal)) continue; // a component's own custom property
                    if (LookProperty().IsMatch(property))
                        yield return $"{relative}|{property}: {declaration[(colon + 1)..].Trim()}";
                }
            }
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }

    [GeneratedRegex("style=\"([^\"]*)\"", RegexOptions.Singleline)]
    private static partial Regex InlineStyle();

    [GeneratedRegex("^(color|background(-[a-z]+)?|border(-[a-z]+)*|padding(-[a-z]+)?|margin(-[a-z]+)?|font(-[a-z]+)?)$")]
    private static partial Regex LookProperty();
}
