using Qertum.Services;

namespace Qertum.Web.Components.Issuers;

/// <summary>Orders issuers for display: each root followed by its descendants, depth-first.</summary>
public static class IssuerTree
{
    public sealed record Line(IssuerResponse Issuer, int Depth);

    /// <summary>
    /// Roots first (oldest first), each followed by its descendants depth-first; issuers whose parent
    /// is not in the list are shown at depth 0 at the end.
    /// </summary>
    public static IReadOnlyList<Line> Build(IReadOnlyList<IssuerResponse> issuers)
    {
        var ordered = issuers.OrderBy(i => i.CreatedAtUtc).ThenBy(i => i.Name, StringComparer.Ordinal).ToList();
        var ids = ordered.Select(i => i.Id).ToHashSet();
        var children = ordered.Where(i => i.ParentIssuerId is { } p && ids.Contains(p))
            .ToLookup(i => i.ParentIssuerId!.Value);
        var lines = new List<Line>();
        var placed = new HashSet<IssuerId>();

        void Add(IssuerResponse issuer, int depth)
        {
            // Guards against a parent cycle in malformed data.
            if (!placed.Add(issuer.Id)) return;
            lines.Add(new Line(issuer, depth));
            foreach (var child in children[issuer.Id])
                Add(child, depth + 1);
        }

        foreach (var root in ordered.Where(i => i.ParentIssuerId is null))
            Add(root, 0);
        foreach (var orphan in ordered.Where(i => !placed.Contains(i.Id)))
            Add(orphan, 0);
        return lines;
    }
}
