using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>
/// Validity bucket for an issued certificate, as the certificates list filters on. Derived from the
/// request's status and <c>ValidTo</c> rather than stored, and the buckets are mutually exclusive:
/// every issued certificate falls in exactly one.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuedCertificateFilter
{
    /// <summary>Issued, and not due to expire within <see cref="IssuedCertificateCounts.ExpiringWindowDays"/>.</summary>
    Valid = 0,
    /// <summary>Issued, still valid, but expiring within <see cref="IssuedCertificateCounts.ExpiringWindowDays"/>.</summary>
    Expiring = 1,
    /// <summary>Issued, and already past its <c>ValidTo</c>.</summary>
    Expired = 2,
    /// <summary>Revocation is queued; the queue consumer has not finalized it yet.</summary>
    Revoking = 3,
    /// <summary>Revocation is final.</summary>
    Revoked = 4
}

/// <summary>Per-bucket counts for the certificates list's filter chips.</summary>
public sealed class IssuedCertificateCounts
{
    /// <summary>
    /// How far ahead a certificate counts as expiring. Deliberately fixed, and deliberately not
    /// <c>CaSettings.ExpiringSoonDays</c>: this labels a list chip, while that setting drives the
    /// dashboard's expiring-soon figure, and silently tying the two would change what the chip means
    /// whenever an operator retunes the dashboard.
    /// </summary>
    public const int ExpiringWindowDays = 30;

    /// <summary>Number of certificates per bucket, keyed by the bucket name (for example <c>"Expiring"</c>).</summary>
    public IReadOnlyDictionary<string, int> ByFilter { get; init; } = new Dictionary<string, int>();

    /// <summary>Total certificates across every bucket, matching the same search.</summary>
    public int Total { get; init; }

    /// <summary>Count for one bucket; zero when nothing falls in it.</summary>
    /// <param name="filter">Bucket to read the count for.</param>
    /// <returns>Number of certificates in <paramref name="filter"/>.</returns>
    public int CountFor(IssuedCertificateFilter filter) =>
        ByFilter.TryGetValue(filter.ToString(), out var count) ? count : 0;
}
