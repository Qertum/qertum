using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Routing;

namespace Qertum.Web.Components.Layout;

/// <summary>
/// A <see cref="NavLink"/> that is active only when the current <c>status</c> query value matches its own.
/// </summary>
/// <remarks>
/// A plain <see cref="NavLink"/> matches on the path, so "All Requests" (<c>certificate-requests</c>) and
/// "Pending" (<c>certificate-requests?status=Pending</c>) would both be highlighted at once. Only
/// <c>status</c> is compared: <c>page</c> and any other key are views of the same menu item, so page 2 of
/// Pending still highlights Pending. The unfiltered link also claims every status that no other menu item
/// names (see <see cref="StatusesLinkedElsewhere"/>), so choosing the Approved chip highlights "All
/// Requests" rather than nothing.
/// </remarks>
public sealed class QueryNavLink : NavLink
{
    private const string StatusKey = "status";

    [Inject] private NavigationManager Navigation { get; set; } = default!;

    /// <summary>
    /// For a link without a <c>status</c> of its own: the statuses another menu item links to, which this
    /// link must not also claim. Ignored on a link that names a status.
    /// </summary>
    [Parameter] public IReadOnlyCollection<string> StatusesLinkedElsewhere { get; set; } = [];

    protected override bool ShouldMatch(string uriAbsolute)
    {
        var href = AdditionalAttributes?.TryGetValue("href", out var value) == true ? value?.ToString() : null;
        var hrefUri = Navigation.ToAbsoluteUri(href ?? string.Empty);
        var currentUri = new Uri(uriAbsolute);

        // The path is compared here rather than by the base class, whose prefix match runs over the
        // whole string, query included — "?page=2&status=Pending" would not match "?status=Pending".
        if (!PathMatches(hrefUri, currentUri))
        {
            return false;
        }

        var expected = StatusOf(hrefUri);
        var current = StatusOf(currentUri);

        if (expected is not null)
        {
            return string.Equals(expected, current, StringComparison.OrdinalIgnoreCase);
        }

        return current is null || !StatusesLinkedElsewhere.Contains(current, StringComparer.OrdinalIgnoreCase);
    }

    private bool PathMatches(Uri href, Uri current)
    {
        var hrefPath = href.GetLeftPart(UriPartial.Path).TrimEnd('/');
        var currentPath = current.GetLeftPart(UriPartial.Path).TrimEnd('/');

        if (string.Equals(hrefPath, currentPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return Match == NavLinkMatch.Prefix
            && currentPath.StartsWith(hrefPath + "/", StringComparison.OrdinalIgnoreCase);
    }

    private static string? StatusOf(Uri uri)
    {
        foreach (var pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=');
            var key = separator < 0 ? pair : pair[..separator];
            if (string.Equals(Uri.UnescapeDataString(key), StatusKey, StringComparison.OrdinalIgnoreCase))
            {
                var status = separator < 0 ? string.Empty : Uri.UnescapeDataString(pair[(separator + 1)..]);
                return status.Length == 0 ? null : status;
            }
        }

        return null;
    }
}
