namespace Qertum.Services;

/// <summary>
/// Per-status certificate request counts, backing the request list's filter chips.
/// </summary>
/// <remarks>
/// Deliberately separate from the dashboard summary, which counts <see cref="CertificateRequestStatus.Revoked"/>
/// inside its issued total. Each chip filters on exactly one status, so the chips need the counts kept apart.
/// </remarks>
public sealed class CertificateRequestStatusCounts
{
    /// <summary>
    /// Number of requests per status, keyed by the status name (for example <c>"Pending"</c>).
    /// A status with no matching rows may be absent rather than present with a zero.
    /// </summary>
    public IReadOnlyDictionary<string, int> ByStatus { get; init; } = new Dictionary<string, int>();

    /// <summary>Total number of requests across every status, matching the same search.</summary>
    public int Total { get; init; }

    /// <summary>Count for a single status; zero when no request currently holds it.</summary>
    /// <param name="status">Status to read the count for.</param>
    /// <returns>Number of requests in <paramref name="status"/>.</returns>
    public int CountFor(CertificateRequestStatus status) =>
        ByStatus.TryGetValue(status.ToString(), out var count) ? count : 0;
}
