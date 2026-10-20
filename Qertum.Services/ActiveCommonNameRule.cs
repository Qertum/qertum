using Microsoft.EntityFrameworkCore;

namespace Qertum.Services;

/// <summary>
/// The active-common-name uniqueness rule, shared by the create path and the preview that predicts
/// it. Both halves must keep matching <c>IX_CertificateRequests_CommonName_Active</c>: a check
/// stricter than the index rejects rows the index would have accepted.
/// </summary>
internal static class ActiveCommonNameRule
{
    /// <summary>
    /// Whether the rule governs this request at all. Root CA requests are unique by type, not by CN,
    /// and a renewal deliberately reuses the CN of the certificate it replaces — the index's
    /// <c>RenewedFromId IS NULL</c> arm.
    /// </summary>
    public static bool Applies(CertificateRequest request) =>
        request.Type != WellKnownCertificateTypes.RootCa && !request.RenewedFromId.HasValue;

    /// <summary>Whether a non-terminal request already holds <paramref name="commonName"/>.</summary>
    public static Task<bool> IsTakenAsync(CertificateRequestDbContext db, string commonName, CancellationToken ct) =>
        db.CertificateRequests.AnyAsync(r =>
            r.CommonName == commonName &&
            r.Status != CertificateRequestStatus.Rejected &&
            r.Status != CertificateRequestStatus.Revoked, ct);
}
