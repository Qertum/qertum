namespace Qertum.Services;

/// <summary>
/// The published CRL's cache entries. Both the API that writes them and the queue consumer that
/// invalidates them after finalising a revocation address the same keys, so they live here rather
/// than being spelled out in either of them.
/// </summary>
public static class CrlCache
{
    /// <summary>Cache key holding the DER-encoded full CRL.</summary>
    public const string Key = "crl:der:v1";

    /// <summary>
    /// Cache key holding the DER-encoded delta CRL. Evicted alongside <see cref="Key"/> whenever a
    /// revocation is finalised, and whenever the full CRL regenerates (a new base makes any cached
    /// delta computed against the old one stale).
    /// </summary>
    public const string DeltaKey = "crl:delta:der:v1";

    /// <summary>Full-CRL cache key of <paramref name="issuer"/>; the legacy issuer keeps <see cref="Key"/>.</summary>
    public static string KeyFor(Issuer issuer) => issuer.LegacyFiles ? Key : $"crl:der:v1:{issuer.Id.Value:N}";

    /// <summary>Delta-CRL cache key of <paramref name="issuer"/>; the legacy issuer keeps <see cref="DeltaKey"/>.</summary>
    public static string DeltaKeyFor(Issuer issuer) => issuer.LegacyFiles ? DeltaKey : $"crl:delta:der:v1:{issuer.Id.Value:N}";
}
