using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

internal static class IssuerQueries
{
    /// <summary>True when a revoked certificate has taken at least one issuer out of service.</summary>
    public static Task<bool> AnyRevokedAsync(CertificateRequestDbContext db, CancellationToken ct) =>
        db.Issuers.AsNoTracking().AnyAsync(i => i.RevokedAtUtc != null, ct);

    /// <summary>
    /// Issuers no client can build a valid chain through at <paramref name="now"/>: the certificate is revoked or
    /// expired, or so is one above it (bounded like the HardStop walk). The one definition behind "show only valid";
    /// <c>Legacy</c> says whether certificates with no <c>IssuerId</c> (the legacy-files issuer) are under one.
    /// </summary>
    public static (HashSet<IssuerId> Ids, bool Legacy) Broken(IEnumerable<Issuer> issuers, DateTime now)
    {
        var byId = issuers.ToDictionary(i => i.Id);
        var broken = new HashSet<IssuerId>();
        foreach (var issuer in byId.Values)
        {
            var current = issuer;
            for (var depth = 0; current is not null && depth <= 16; depth++)
            {
                if (current.RevokedAtUtc is not null || current.ValidTo <= now)
                {
                    broken.Add(issuer.Id);
                    break;
                }
                current = current.ParentIssuerId is { } parent ? byId.GetValueOrDefault(parent) : null;
            }
        }
        return (broken, byId.Values.Any(i => i.LegacyFiles && broken.Contains(i.Id)));
    }

    /// <inheritdoc cref="Broken(IEnumerable{Issuer}, DateTime)"/>
    public static async Task<(HashSet<IssuerId> Ids, bool Legacy)> BrokenAsync(CertificateRequestDbContext db, DateTime now, CancellationToken ct) =>
        Broken(await db.Issuers.AsNoTracking()
            .Select(i => new Issuer { Id = i.Id, ParentIssuerId = i.ParentIssuerId, RevokedAtUtc = i.RevokedAtUtc, ValidTo = i.ValidTo, LegacyFiles = i.LegacyFiles })
            .ToListAsync(ct), now);

    /// <summary>
    /// The kind of the most recently revoked issuer whose own parent is not revoked (the one whose revocation took
    /// the others with it under HardStop), or null when none is revoked.
    /// </summary>
    public static async Task<IssuerKind?> LatestRevokedKindAsync(CertificateRequestDbContext db, CancellationToken ct)
    {
        var revoked = await db.Issuers.AsNoTracking().Where(i => i.RevokedAtUtc != null)
            .Select(i => new { i.Id, i.ParentIssuerId, i.Kind, i.RevokedAtUtc }).ToListAsync(ct);
        var revokedIds = revoked.Select(i => i.Id).ToHashSet();
        return revoked.Where(i => i.ParentIssuerId is not { } parent || !revokedIds.Contains(parent))
            .OrderByDescending(i => i.RevokedAtUtc).Select(i => (IssuerKind?)i.Kind).FirstOrDefault();
    }

    /// <summary>
    /// The issuer that now stands in for <paramref name="id"/>: the end of the chain of replacements, following
    /// <c>RenewalOfIssuerId</c> forward through successors that got a certificate (any status but pending, so a
    /// replacement that was itself renewed is walked through; bounded at 16 steps), or the issuer itself when it was
    /// never renewed. Renewals sign under it; whether it can sign is the caller's check.
    /// </summary>
    public static async Task<Issuer?> CurrentReplacementAsync(CertificateRequestDbContext db, IssuerId id, CancellationToken ct)
    {
        var current = await db.Issuers.AsNoTracking().FirstOrDefaultAsync(i => i.Id == id, ct);
        for (var depth = 0; current is not null && depth < 16; depth++)
        {
            var currentId = current.Id;
            var next = await db.Issuers.AsNoTracking()
                .Where(i => i.RenewalOfIssuerId == currentId && i.Status != IssuerStatus.PendingCertificate)
                .OrderByDescending(i => i.ActivatedAtUtc).ThenByDescending(i => i.CreatedAtUtc).FirstOrDefaultAsync(ct);
            if (next is null) break;
            current = next;
        }
        return current;
    }

    /// <summary>
    /// The issuer a RootCA request created (tracked): its <c>IssuerId</c>, or the legacy-files row for a request
    /// from before issuers had ids. Revoking and renewing a root both start here.
    /// </summary>
    public static Task<Issuer?> RootIssuerOfAsync(CertificateRequestDbContext db, CertificateRequest rootRequest, CancellationToken ct) =>
        rootRequest.IssuerId is { } id
            ? db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct)
            : db.Issuers.FirstOrDefaultAsync(i => i.LegacyFiles, ct);

    /// <summary>
    /// Unexpired certificates <paramref name="issuer"/> signed (Issued, PendingRevocation or Revoked — a
    /// pair's PQC leg shares the row's <c>ValidTo</c>, so rows cover both legs) plus its unexpired child CAs.
    /// Revoked-but-unexpired counts: relying parties still ask its CRL and OCSP about them.
    /// </summary>
    public static async Task<int> UnexpiredCountAsync(CertificateRequestDbContext db, Issuer issuer, DateTime now, CancellationToken ct)
    {
        var certificates = await db.CertificateRequests.CountAsync(r =>
            (r.IssuerId == issuer.Id || (issuer.LegacyFiles && r.IssuerId == null)) &&
            r.CertificatePem != null &&
            (r.Status == CertificateRequestStatus.Issued || r.Status == CertificateRequestStatus.PendingRevocation ||
             r.Status == CertificateRequestStatus.Revoked) &&
            r.ValidTo != null && r.ValidTo > now, ct);
        var childCas = await db.Issuers.CountAsync(i =>
            i.ParentIssuerId == issuer.Id && i.ValidTo != null && i.ValidTo > now &&
            i.Status != IssuerStatus.Archived && i.Status != IssuerStatus.Destroyed, ct);
        return certificates + childCas;
    }
}
