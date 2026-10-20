using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

/// <summary>
/// Registers the pre-hierarchy CA (<c>CaData/ca.key</c> + <c>ca.pem</c>) as issuer #1. Runs at
/// ApiService startup after the schema is applied, and lazily from <see cref="IssuerRegistry"/>
/// whenever the table is empty — so a CA created by onboarding after startup, and any host that
/// starts before ApiService finished, still see a row. Idempotent and race-safe: the id is derived
/// from the key, so concurrent callers insert the same primary key and all but one lose harmlessly.
/// </summary>
public static class IssuerBootstrap
{
    public const string PerformedBy = "issuer-bootstrap";

    /// <summary>A GUID made of the first 16 bytes of the SPKI hash.</summary>
    public static IssuerId LegacyIdFor(string spkiSha256) =>
        new(new Guid(Convert.FromHexString(spkiSha256)[..16]));

    /// <summary>
    /// Returns the default issuer when one exists, the newly registered legacy issuer when the table was
    /// empty and the legacy files exist, else null. Never registers the legacy files once any row
    /// exists: after a force replace they may linger and must not come back.
    /// </summary>
    public static async Task<Issuer?> EnsureLegacyIssuerAsync(
        CertificateRequestDbContext db,
        ICertificateGenerator legacy,
        IAuditLogService? audit,
        TimeProvider clock,
        CancellationToken ct)
    {
        if (await db.Issuers.AnyAsync(ct))
            return await db.Issuers.AsNoTracking().FirstOrDefaultAsync(i => i.IsDefault, ct);

        if (!legacy.IsInitialized)
            return null;

        var pem = legacy.GetCaCertificatePem();
        var facts = IssuerCertificateFacts.Read(pem);
        var now = clock.GetUtcNow().UtcDateTime;
        var issuer = new Issuer
        {
            Id = LegacyIdFor(facts.SpkiSha256),
            Name = NameFrom(facts.SubjectDn),
            Kind = facts.IsSelfSigned ? IssuerKind.Root : IssuerKind.Intermediate,
            KeyCustody = IssuerKeyCustody.Online,
            Status = IssuerStatus.Active,
            IsDefault = true,
            LegacyFiles = true,
            CertificatePem = pem,
            CreatedAtUtc = now,
            ActivatedAtUtc = now
        };
        facts.ApplyTo(issuer);

        db.Issuers.Add(issuer);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Another host won the race with the same id; use its row.
            db.ChangeTracker.Clear();
            return await db.Issuers.AsNoTracking().FirstOrDefaultAsync(i => i.IsDefault, ct);
        }

        // Every certificate on record was signed by the only CA that existed.
        await db.CertificateRequests
            .Where(r => r.IssuerId == null && r.CertificatePem != null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.IssuerId, issuer.Id), ct);

        if (audit is not null)
            await audit.LogAsync("IssuerRegistered", PerformedBy, (Guid)issuer.Id, issuer.Name,
                "Existing CA registered as issuer #1 (root, online, default).", ct);

        return issuer;
    }

    /// <summary>The CN of <paramref name="subjectDn"/>, or the whole DN when it has none; at most 200 chars.</summary>
    internal static string NameFrom(string subjectDn)
    {
        var cn = subjectDn.Split(',', StringSplitOptions.TrimEntries)
            .FirstOrDefault(p => p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))?[3..];
        var name = string.IsNullOrWhiteSpace(cn) ? subjectDn : cn;
        return name.Length <= 200 ? name : name[..200];
    }
}
