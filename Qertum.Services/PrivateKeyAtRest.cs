using Microsoft.EntityFrameworkCore;

namespace Qertum.Services;

/// <summary>
/// Re-encrypts private keys that an older version stored as plain PEM: <c>PqcPrivateKeyPem</c>
/// (the second key of a paired or hybrid pair) had no at-rest converter before 1.0.0-rc3, and the
/// earliest <c>PrivateKeyPem</c> rows predate encryption. The converter reads plain PEM, so such
/// rows keep working; saving them again writes them encrypted. Run once by ApiService at start,
/// after the schema is applied; a second run finds nothing.
/// </summary>
public static class PrivateKeyAtRest
{
    private const int BatchSize = 200;

    /// <summary>Encrypts every row holding a plain-PEM key; returns how many rows were rewritten.</summary>
    public static async Task<int> EncryptPlainKeysAsync(CertificateRequestDbContext db, CancellationToken cancellationToken = default)
    {
        // The filter must see the stored text, not the converted value, hence raw SQL for the ids.
        var ids = await db.Database
            .SqlQueryRaw<Guid>(
                "SELECT \"Id\" AS \"Value\" FROM \"CertificateRequests\" " +
                "WHERE \"PrivateKeyPem\" LIKE '-----BEGIN%' OR \"PqcPrivateKeyPem\" LIKE '-----BEGIN%'")
            .ToListAsync(cancellationToken);

        foreach (var batch in ids.Chunk(BatchSize))
        {
            var requestIds = batch.Select(id => new CertificateRequestId(id)).ToList();
            var rows = await db.CertificateRequests.Where(r => requestIds.Contains(r.Id)).ToListAsync(cancellationToken);
            foreach (var row in rows)
            {
                // Unchanged values are not written unless marked; marking makes the converter encrypt them.
                db.Entry(row).Property(r => r.PrivateKeyPem).IsModified = row.PrivateKeyPem is not null;
                db.Entry(row).Property(r => r.PqcPrivateKeyPem).IsModified = row.PqcPrivateKeyPem is not null;
            }
            await db.SaveChangesAsync(cancellationToken);
            db.ChangeTracker.Clear();
        }
        return ids.Count;
    }
}
