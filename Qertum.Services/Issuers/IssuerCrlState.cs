using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

/// <summary>
/// Per-issuer CRL number and delta base. The legacy issuer keeps using CaSettings' columns so a
/// mixed-version rollout, where older hosts still claim from CaSettings, never publishes a
/// non-increasing number; every other issuer counts on its own row.
/// </summary>
public sealed class IssuerCrlState(CertificateRequestDbContext db, ICertificateRequestService requests)
{
    public async Task<long> ClaimNextCrlNumberAsync(Issuer issuer, CancellationToken ct)
    {
        if (issuer.LegacyFiles) return await requests.ClaimNextCrlNumberAsync(ct);

        // Single UPDATE ... SET CrlNumber = CrlNumber + 1: two hosts claim distinct numbers.
        await db.Issuers.Where(i => i.Id == issuer.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.CrlNumber, i => i.CrlNumber + 1), ct);
        return await db.Issuers.AsNoTracking().Where(i => i.Id == issuer.Id).Select(i => i.CrlNumber).SingleAsync(ct);
    }

    public async Task RecordBaseCrlAsync(Issuer issuer, long crlNumber, DateTime thisUpdateUtc, CancellationToken ct)
    {
        if (issuer.LegacyFiles)
        {
            await requests.RecordBaseCrlAsync(crlNumber, thisUpdateUtc, ct);
            return;
        }
        await db.Issuers.Where(i => i.Id == issuer.Id).ExecuteUpdateAsync(s => s
            .SetProperty(i => i.BaseCrlNumber, crlNumber)
            .SetProperty(i => i.BaseCrlThisUpdateUtc, thisUpdateUtc), ct);
    }

    public async Task<(long? Number, DateTime? ThisUpdateUtc)> GetBaseAsync(Issuer issuer, CancellationToken ct)
    {
        if (issuer.LegacyFiles)
        {
            // Read-only: must not create the settings row.
            var s = await db.Settings.AsNoTracking().Select(x => new { x.BaseCrlNumber, x.BaseCrlThisUpdateUtc }).FirstOrDefaultAsync(ct);
            return (s?.BaseCrlNumber, s?.BaseCrlThisUpdateUtc);
        }
        var row = await db.Issuers.AsNoTracking().Where(i => i.Id == issuer.Id)
            .Select(i => new { i.BaseCrlNumber, i.BaseCrlThisUpdateUtc }).SingleAsync(ct);
        return (row.BaseCrlNumber, row.BaseCrlThisUpdateUtc);
    }
}
