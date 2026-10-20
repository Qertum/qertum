namespace Qertum.Services.Issuers;

/// <summary>The CA-specific extensions of a subordinate CA certificate. Lists hold normalized DNS suffixes / CIDRs.</summary>
public sealed record SubordinateCaProfile(
    int? PathLength,
    IReadOnlyList<string> PermittedDnsSuffixes,
    IReadOnlyList<string> ExcludedDnsSuffixes,
    IReadOnlyList<string> PermittedIpRanges,
    IReadOnlyList<string> ExcludedIpRanges)
{
    /// <summary>cA without pathLen or name constraints.</summary>
    public static SubordinateCaProfile Unconstrained { get; } = new(null, [], [], [], []);

    /// <summary>Whether any NameConstraints subtree is set.</summary>
    public bool HasNameConstraints =>
        PermittedDnsSuffixes.Count + ExcludedDnsSuffixes.Count + PermittedIpRanges.Count + ExcludedIpRanges.Count > 0;
}

/// <summary>One entry of an offline root's CRL.</summary>
public sealed record OfflineRevocation(string SerialHex, DateTime RevokedAtUtc, string? Reason);
