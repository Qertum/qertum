using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

/// <summary>
/// Per-issuer CRL number and delta base. The legacy issuer keeps using CaSettings' columns so a
/// mixed-version rollout, where older hosts still claim from CaSettings, never publishes a
/// non-increasing number; every other issuer counts on its own row.
/// </summary>
public sealed class IssuerCrlState(CertificateRequestDbContext db, ICertificateRequestService requests)
{
    /// <summary>
    /// Reserves a durable CRL number, then serializes snapshot, signing and cache publication with
    /// other hosts and revocation writers. A number overtaken before acquiring the publication
    /// lock is abandoned and retried. Keeping the reservation in its own committed transaction
    /// prevents a failed or interrupted cache write from making an exposed number reusable.
    /// </summary>
    internal async Task<T> PublishAsync<T>(Issuer issuer, Func<long, Task<T>> publish, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null)
            throw new InvalidOperationException("CRL publication requires its own transaction to reserve a durable number.");

        while (true)
        {
            var number = await ClaimNextCrlNumberAsync(issuer, ct);
            var (published, result) = await InWriteTransactionAsync(db, async () =>
            {
                var latest = issuer.LegacyFiles
                    ? await db.Settings.AsNoTracking().Where(s => s.Id == 1).Select(s => s.CrlNumber).SingleAsync(ct)
                    : await db.Issuers.AsNoTracking().Where(i => i.Id == issuer.Id).Select(i => i.CrlNumber).SingleAsync(ct);
                if (latest != number) return (false, default(T)!);
                return (true, await publish(number));
            }, ct);
            if (published) return result;
        }
    }

    public async Task<long> ClaimNextCrlNumberAsync(Issuer issuer, CancellationToken ct)
    {
        if (issuer.LegacyFiles) return await requests.ClaimNextCrlNumberAsync(ct);

        // The increment and the read of the claimed value run in one write transaction: the UPDATE takes the
        // database's write lock, so no other publisher can increment again before this one has read its number.
        // Two separate statements let two concurrent publishers both read the final value and sign different CRLs
        // with the same number (AI Scan, 1.0.0-rc6).
        return await InWriteTransactionAsync(db, async () =>
        {
            await db.Issuers.Where(i => i.Id == issuer.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(i => i.CrlNumber, i => i.CrlNumber + 1), ct);
            return await db.Issuers.AsNoTracking().Where(i => i.Id == issuer.Id).Select(i => i.CrlNumber).SingleAsync(ct);
        }, ct);
    }

    /// <summary>
    /// Records <paramref name="crlNumber"/> as the issuer's delta base and runs <paramref name="publish"/> (the cache
    /// writes) while holding the database write lock, but only when no newer base is recorded. Returns false, and
    /// publishes nothing, when a publisher that claimed a higher number got there first: an older CRL must never
    /// replace a newer one in the cache or as the base. An exception from <paramref name="publish"/> leaves the base
    /// unrecorded.
    /// </summary>
    public async Task<bool> RecordBaseCrlIfNewerAsync(Issuer issuer, long crlNumber, DateTime thisUpdateUtc,
        Func<Task> publish, CancellationToken ct)
    {
        await using var transaction = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var recorded = issuer.LegacyFiles
            ? await db.Settings.Where(s => s.Id == 1 && (s.BaseCrlNumber == null || s.BaseCrlNumber < crlNumber))
                .ExecuteUpdateAsync(s => s
                    .SetProperty(x => x.BaseCrlNumber, crlNumber)
                    .SetProperty(x => x.BaseCrlThisUpdateUtc, thisUpdateUtc), ct)
            : await db.Issuers.Where(i => i.Id == issuer.Id && (i.BaseCrlNumber == null || i.BaseCrlNumber < crlNumber))
                .ExecuteUpdateAsync(s => s
                    .SetProperty(i => i.BaseCrlNumber, crlNumber)
                    .SetProperty(i => i.BaseCrlThisUpdateUtc, thisUpdateUtc), ct);
        if (recorded == 0) return false;

        await publish();
        if (transaction is not null) await transaction.CommitAsync(ct);
        if (issuer.LegacyFiles && db.Settings.Local.FirstOrDefault(s => s.Id == 1) is { } tracked)
            await db.Entry(tracked).ReloadAsync(ct);
        return true;
    }

    /// <summary>Runs <paramref name="work"/> in a write transaction of its own, or in the caller's when one is open.</summary>
    internal static async Task<T> InWriteTransactionAsync<T>(DbContext db, Func<Task<T>> work, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) return await work();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var result = await work();
        await transaction.CommitAsync(ct);
        return result;
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
