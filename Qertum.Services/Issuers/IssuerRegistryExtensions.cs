namespace Qertum.Services.Issuers;

public static class IssuerRegistryExtensions
{
    /// <summary>
    /// The issuer behind the unprefixed <c>/crl</c> and <c>/crl/delta</c>: the legacy issuer while it is
    /// Active or Retired — its leaves carry <c>CaSettings.CrlDistributionPoint</c>, which points there, so a
    /// rollover must not swap in another CA's CRL — else the default issuer.
    /// </summary>
    public static async Task<IssuerHandle?> ForUnscopedCrlAsync(this IIssuerRegistry issuers, CancellationToken ct = default)
    {
        var legacy = (await issuers.GetAllAsync(ct))
            .FirstOrDefault(i => i.LegacyFiles && i.Status is IssuerStatus.Active or IssuerStatus.Retired);
        return legacy is not null ? await issuers.GetAsync(legacy.Id, ct) : await issuers.GetDefaultAsync(ct);
    }
}
