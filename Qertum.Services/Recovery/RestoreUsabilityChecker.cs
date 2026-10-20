using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Services.Recovery;

/// <summary>
/// Opens a restored data directory the way a host would, without starting a host, and checks that the restored
/// database, key ring and CA keys still work: that it signs, decrypts stored secrets and builds a CRL that lists
/// every revoked certificate. Reads and signs in memory; publishes and persists nothing.
/// </summary>
/// <param name="db">The restored database.</param>
/// <param name="issuers">The issuer registry over the restored CA files.</param>
/// <param name="requests">Used for the unpaged revoked-certificate projection the CRL publisher uses.</param>
/// <param name="timeProvider">The clock for the throwaway CRL.</param>
public sealed class RestoreUsabilityChecker(
    CertificateRequestDbContext db,
    IIssuerRegistry issuers,
    ICertificateRequestService requests,
    TimeProvider timeProvider)
{
    /// <summary>Check name: schema state of the restored database.</summary>
    public const string DatabaseCheck = "database";

    /// <summary>Check name: a stored secret decrypts with the restored key ring.</summary>
    public const string KeyRingCheck = "key-ring";

    /// <summary>Check name: every online active issuer signs a probe certificate that chains to its root.</summary>
    public const string SigningCheck = "signing";

    /// <summary>Check name: a CRL is built, signed correctly and lists every revoked serial.</summary>
    public const string RevocationCheck = "revocation";

    private const string ProtectedPrefix = "CfDJ8";

    /// <summary>Runs the four checks in order. When the database check does not pass, the rest are not exercised.</summary>
    /// <param name="ct">Cancellation.</param>
    public async Task<RestoreUsabilityReport> RunAsync(CancellationToken ct = default)
    {
        var results = new List<RestoreCheckResult>();
        var database = await GuardedAsync(DatabaseCheck, () => CheckDatabaseAsync(ct));
        results.Add(database);
        if (database.Outcome != RestoreCheckOutcome.Pass)
        {
            foreach (var name in new[] { KeyRingCheck, SigningCheck, RevocationCheck })
                results.Add(new RestoreCheckResult(name, RestoreCheckOutcome.NotExercised, "the database check did not pass"));
            return new RestoreUsabilityReport(results);
        }

        results.Add(await GuardedAsync(KeyRingCheck, () => CheckKeyRingAsync(ct)));
        results.Add(await GuardedAsync(SigningCheck, () => CheckSigningAsync(ct)));
        results.Add(await GuardedAsync(RevocationCheck, () => CheckRevocationAsync(ct)));
        return new RestoreUsabilityReport(results);
    }

    private static async Task<RestoreCheckResult> GuardedAsync(string name, Func<Task<RestoreCheckResult>> run)
    {
        try
        {
            return await run();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The exception type only: a message can carry paths or content.
            return new RestoreCheckResult(name, RestoreCheckOutcome.Fail, $"{ex.GetType().Name}: the check could not complete");
        }
    }

    private async Task<RestoreCheckResult> CheckDatabaseAsync(CancellationToken ct)
    {
        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).Count();
        if (pending > 0)
            return new(DatabaseCheck, RestoreCheckOutcome.NotTestable,
                $"{pending} migration(s) of this image are not applied; the backup is older than this image, so use the image version that wrote it");

        var known = db.Database.GetMigrations().ToHashSet(StringComparer.Ordinal);
        var ahead = (await db.Database.GetAppliedMigrationsAsync(ct)).Count(m => !known.Contains(m));
        if (ahead > 0)
            return new(DatabaseCheck, RestoreCheckOutcome.NotTestable,
                $"the database is {ahead} migration(s) ahead of this image; use the image version that wrote the backup");

        var hasSettings = await db.Settings.AsNoTracking().AnyAsync(s => s.Id == 1, ct);
        return new(DatabaseCheck, RestoreCheckOutcome.Pass,
            hasSettings ? "schema current, CA settings present" : "schema current, no CA settings yet (CA not onboarded)");
    }

    private async Task<RestoreCheckResult> CheckKeyRingAsync(CancellationToken ct)
    {
        // Only a value that still carries the Data Protection header proves anything: a legacy plain PEM
        // "decrypts" trivially, and DecryptOrPassThrough returns null (not an exception) for a protected value the
        // restored key ring cannot open.
        var requestId = await FirstIdAsync(
            "SELECT CAST(\"Id\" AS TEXT) AS Value FROM \"CertificateRequests\" " +
            $"WHERE \"Status\" = 'Issued' AND \"PrivateKeyPem\" LIKE '{ProtectedPrefix}%' ORDER BY \"UpdatedAtUtc\" DESC LIMIT 1", ct);
        if (requestId is { } id)
        {
            var typed = new CertificateRequestId(id);
            var pem = await db.CertificateRequests.AsNoTracking().Where(r => r.Id == typed).Select(r => r.PrivateKeyPem).FirstOrDefaultAsync(ct);
            return pem is not null && pem.StartsWith("-----BEGIN", StringComparison.Ordinal)
                ? new(KeyRingCheck, RestoreCheckOutcome.Pass, "decrypted a stored issued private key")
                : new(KeyRingCheck, RestoreCheckOutcome.Fail, "a stored issued private key cannot be decrypted with the restored key ring");
        }

        var webhookId = await FirstIdAsync(
            $"SELECT CAST(\"Id\" AS TEXT) AS Value FROM \"Webhooks\" WHERE \"Secret\" LIKE '{ProtectedPrefix}%' LIMIT 1", ct);
        if (webhookId is { } hook)
        {
            var typed = new WebhookId(hook);
            var secret = await db.Webhooks.AsNoTracking().Where(w => w.Id == typed).Select(w => w.Secret).FirstOrDefaultAsync(ct);
            return !string.IsNullOrEmpty(secret)
                ? new(KeyRingCheck, RestoreCheckOutcome.Pass, "decrypted a stored webhook secret")
                : new(KeyRingCheck, RestoreCheckOutcome.Fail, "a stored webhook secret cannot be decrypted with the restored key ring");
        }

        return new(KeyRingCheck, RestoreCheckOutcome.NotExercised, "no encrypted private key or webhook secret is stored");
    }

    private async Task<Guid?> FirstIdAsync(string sql, CancellationToken ct)
    {
        var rows = await db.Database.SqlQueryRaw<string>(sql).ToListAsync(ct);
        return rows.Count > 0 && Guid.TryParse(rows[0], out var id) ? id : null;
    }

    private async Task<RestoreCheckResult> CheckSigningAsync(CancellationToken ct)
    {
        var tested = 0;
        var offline = 0;
        var failures = new List<string>();
        var probeSettings = new CaSettings { PqcStage = PqcStage.Off };

        foreach (var issuer in (await issuers.GetAllAsync(ct)).Where(i => i.Status == IssuerStatus.Active))
        {
            if (issuer.KeyCustody == IssuerKeyCustody.Offline)
            {
                offline++;
                continue;
            }

            var handle = await issuers.GetAsync(issuer.Id, ct);
            if (handle?.Generator is null)
            {
                failures.Add($"issuer {issuer.Id.Value:N}: the CA key could not be loaded");
                continue;
            }

            var probe = handle.Generator.GenerateCertificate(
                new CertificateRequest { CommonName = "restore-check.invalid", Type = "WebServer" }, probeSettings);
            var leaf = QertumKeyCodec.ReadCertificatePem(probe.CertificatePem);
            var chain = (await issuers.ChainForAsync(issuer.Id, ct)).SelectMany(ChainVerifier.ReadAll).ToList();
            if (leaf is null || ChainVerifier.Build(leaf, chain).Path is null)
                failures.Add($"issuer {issuer.Id.Value:N}: the probe certificate does not chain to its root");
            else
                tested++;
        }

        if (failures.Count > 0)
            return new(SigningCheck, RestoreCheckOutcome.Fail, string.Join("; ", failures));
        if (tested == 0)
            return new(SigningCheck, RestoreCheckOutcome.NotExercised,
                offline > 0 ? $"{offline} offline issuer(s) hold no key here" : "no active online issuer to test");
        return new(SigningCheck, RestoreCheckOutcome.Pass, $"{tested} online issuer(s) signed a probe certificate that chains to its root");
    }

    private async Task<RestoreCheckResult> CheckRevocationAsync(CancellationToken ct)
    {
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, ct) ?? new CaSettings { Id = 1 };
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var tested = 0;
        var listedTotal = 0;
        var failures = new List<string>();

        foreach (var issuer in (await issuers.GetAllAsync(ct)).Where(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired))
        {
            if (issuer.KeyCustody == IssuerKeyCustody.Offline)
                continue;

            var handle = await issuers.GetAsync(issuer.Id, ct);
            if (handle?.Generator is null || !handle.CanSignRevocation)
            {
                failures.Add($"issuer {issuer.Id.Value:N}: cannot sign a CRL");
                continue;
            }

            var revoked = await requests.GetAllRevokedForCrlAsync(handle.Scope, ct);
            var expected = new HashSet<BigInteger>();
            var unreadable = 0;
            foreach (var pem in revoked.SelectMany(r => new[] { r.CertificatePem, r.PqcCertificatePem }).Where(p => !string.IsNullOrWhiteSpace(p)))
            {
                if (QertumKeyCodec.ReadCertificatePem(pem!) is { } cert)
                    expected.Add(cert.SerialNumber);
                else
                    unreadable++;
            }

            // The CRL number is not persisted (nothing is claimed or published), so any value serves.
            var crl = new X509CrlParser().ReadCrl(handle.Generator.GenerateCrl(revoked, settings, 1, now));
            var caCertificate = QertumKeyCodec.ReadCertificatePem(issuer.CertificatePem ?? string.Empty);
            if (caCertificate is null || !crl.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(caCertificate))))
            {
                failures.Add($"issuer {issuer.Id.Value:N}: the CRL signature does not verify against the issuer certificate");
                continue;
            }

            var listed = crl.GetRevokedCertificates()?.Select(c => c.SerialNumber).ToHashSet() ?? [];
            var missing = expected.Count(serial => !listed.Contains(serial));
            if (unreadable > 0 || missing > 0)
            {
                failures.Add($"issuer {issuer.Id.Value:N}: {missing} revoked serial(s) missing from the CRL, {unreadable} revoked certificate(s) unreadable");
                continue;
            }

            tested++;
            listedTotal += expected.Count;
        }

        if (failures.Count > 0)
            return new(RevocationCheck, RestoreCheckOutcome.Fail, string.Join("; ", failures));
        if (tested == 0)
            return new(RevocationCheck, RestoreCheckOutcome.NotExercised, "no online issuer to build a CRL with");
        return new(RevocationCheck, RestoreCheckOutcome.Pass, $"{tested} CRL(s) verified, {listedTotal} revoked serial(s) listed");
    }
}
