namespace Qertum.Services.Acme;

/// <summary>
/// Outcome of a TXT lookup. A failed lookup carries an operator-facing reason rather than throwing,
/// because that reason is written into the challenge's error document and shown to the ACME client.
/// </summary>
public sealed record DnsTxtLookupResult(bool Succeeded, IReadOnlyList<string> Records, string? ErrorDetail);

/// <summary>
/// Reads TXT records for dns-01 validation.
/// </summary>
/// <remarks>
/// This seam reads only. Qertum is the ACME server: publishing the _acme-challenge record is the
/// client's job (that is what certbot's and cert-manager's DNS provider plugins do). If Qertum ever
/// publishes records itself, that belongs behind a separate writing interface — do not grow write
/// methods here.
/// </remarks>
public interface IAcmeDnsResolver
{
    Task<DnsTxtLookupResult> ResolveTxtAsync(string name, CancellationToken ct = default);
}
