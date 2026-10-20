using Qertum.Services.Policies;

namespace Qertum.Services.BulkOperations;

/// <summary>The two single-item actions a bulk run performs; the seam the runner is tested through.</summary>
public interface IBulkItemActions
{
    /// <summary>Queues one certificate for revocation. False when it is no longer <c>Issued</c>.</summary>
    /// <param name="id">The request.</param>
    /// <param name="reason">Revocation reason.</param>
    /// <param name="performedBy">The executing identity's name, for the audit entry.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>True when queued, false when the request was not eligible any more.</returns>
    Task<bool> RevokeAsync(CertificateRequestId id, string reason, string performedBy, CancellationToken ct);

    /// <summary>Files a renewal request; it starts <c>Pending</c>. Throws when policy or the CA refuses.</summary>
    /// <param name="id">The source request.</param>
    /// <param name="performedBy">The executing identity's name.</param>
    /// <param name="caller">The executor as policy sees them.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>The id of the new request.</returns>
    Task<CertificateRequestId> RenewAsync(CertificateRequestId id, string performedBy, CallerContext caller, CancellationToken ct);
}
