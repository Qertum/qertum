namespace Qertum.Services;

/// <summary>
/// Aggregated dashboard statistics for certificate requests and issued certificates.
/// </summary>
public sealed class CertificateDashboardSummary
{
    // ── Request Pipeline ──

    /// <summary>Total number of certificate requests across all statuses.</summary>
    public int TotalCount { get; init; }

    /// <summary>Requests awaiting processing.</summary>
    public int PendingCount { get; init; }

    /// <summary>Requests that have been dequeued and approved, but not yet issued.</summary>
    public int ApprovedCount { get; init; }

    /// <summary>Requests that were denied/rejected.</summary>
    public int RejectedCount { get; init; }

    /// <summary>Certificates that have been issued (including revoked and expired).</summary>
    public int IssuedCount { get; init; }

    // ── Certificate Validity ──

    /// <summary>Issued certificates that are currently valid (more than 30 days until expiry, not revoked).</summary>
    public int ValidCount { get; init; }

    /// <summary>Issued certificates expiring within the next 30 days (not revoked).</summary>
    public int ExpiringSoonCount { get; init; }

    /// <summary>Issued certificates whose ValidTo date has passed.</summary>
    public int ExpiredCount { get; init; }

    /// <summary>Certificates that have been revoked.</summary>
    public int RevokedCount { get; init; }

    // ── Activity ──

    /// <summary>The most recent certificate requests (up to 10).</summary>
    public IReadOnlyList<CertificateRequest> RecentRequests { get; init; } = [];
}
