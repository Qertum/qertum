namespace Qertum.Services.Issuers;

/// <summary>
/// URLs a non-legacy issuer writes into what it signs. Null from <see cref="For"/> means "legacy
/// issuer: use CaSettings exactly as before", which keeps issuer #1's output byte-for-byte unchanged.
/// A null member of a non-null instance means "omit that extension".
/// </summary>
public sealed record IssuerUrls(string? CrlDistributionPoint, string? DeltaCrlDistributionPoint, string? OcspResponderUrl, string? CaIssuersUrl)
{
    public static IssuerUrls? For(Issuer issuer, CaSettings settings)
    {
        if (issuer.LegacyFiles) return null;

        var baseUrl = string.IsNullOrWhiteSpace(settings.PublicBaseUrl) ? null : settings.PublicBaseUrl.TrimEnd('/');
        return new IssuerUrls(
            issuer.CrlDistributionPoint ?? Derive(settings.CrlDistributionPoint, issuer.Id),
            settings.DeltaCrlEnabled ? Derive(settings.CrlDeltaDistributionPoint, issuer.Id) : null,
            // One responder answers for every issuer (it routes by CertID), so the URL is shared.
            issuer.OcspResponderUrl ?? (string.IsNullOrWhiteSpace(settings.OcspResponderUrl) ? null : settings.OcspResponderUrl),
            issuer.CaIssuersUrl ?? (baseUrl is null ? null : $"{baseUrl}/v1/issuers/{issuer.Id}/certificate"));
    }

    /// <summary><paramref name="baseUrl"/> + "/" + id, or null when no base is configured.</summary>
    public static string? Derive(string? baseUrl, IssuerId id) =>
        string.IsNullOrWhiteSpace(baseUrl) ? null : $"{baseUrl.TrimEnd('/')}/{id}";
}
