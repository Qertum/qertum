using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

internal static class IssuerQueries
{
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
