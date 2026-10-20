namespace Qertum.Services.Issuers;

/// <summary>Shared by everything that must act on "each issuer that publishes its own CRL".</summary>
public static class IssuerRegistryCrlExtensions
{
    /// <summary>
    /// The handles whose CRL this CA signs itself: every issuer that can sign revocation, or, for an
    /// unregistered legacy CA, the synthetic default handle (same behaviour as before issuers existed).
    /// </summary>
    public static async Task<IReadOnlyList<IssuerHandle>> GetCrlSigningHandlesAsync(
        this IIssuerRegistry registry, CancellationToken cancellationToken = default)
    {
        var candidates = new List<IssuerHandle>();
        var all = await registry.GetAllAsync(cancellationToken);
        if (all.Count == 0)
        {
            if (await registry.GetDefaultAsync(cancellationToken) is { CanSignRevocation: true } synthetic) candidates.Add(synthetic);
        }
        else
        {
            foreach (var row in all)
                if (await registry.GetAsync(row.Id, cancellationToken) is { CanSignRevocation: true } handle)
                    candidates.Add(handle);
        }
        return candidates;
    }
}
