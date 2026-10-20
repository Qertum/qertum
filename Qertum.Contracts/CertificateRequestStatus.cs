using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Lifecycle status of a certificate request.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CertificateRequestStatus
{
    /// <summary>Submitted and awaiting operator approval.</summary>
    Pending = 0,
    /// <summary>Approved by an operator; queued for issuance.</summary>
    Approved = 1,
    /// <summary>Rejected by an operator.</summary>
    Rejected = 2,
    /// <summary>Certificate has been issued.</summary>
    Issued = 3,
    /// <summary>Issued certificate has been revoked.</summary>
    Revoked = 4,
    /// <summary>Claimed by a queue consumer worker; prevents double-issuance.</summary>
    Processing = 5,
    /// <summary>Revocation queued; the queue consumer will finalize this to <see cref="Revoked"/>.</summary>
    PendingRevocation = 6
}

/// <summary>
/// The one definition of which statuses are on their way somewhere and which are the end. The server
/// (polling hint), <c>ApiClient</c>, the Web UI and the CLI all use it, so the lists cannot drift apart.
/// </summary>
public static class CertificateRequestStatusExtensions
{
    /// <summary>
    /// A status the system is advancing by itself: <see cref="CertificateRequestStatus.Approved"/> and
    /// <see cref="CertificateRequestStatus.Processing"/> until issuance finishes, and
    /// <see cref="CertificateRequestStatus.PendingRevocation"/> until the revocation is finalized.
    /// <see cref="CertificateRequestStatus.Pending"/> is not in progress: it waits for a person.
    /// </summary>
    public static bool IsInProgress(this CertificateRequestStatus status) =>
        status is CertificateRequestStatus.Approved or CertificateRequestStatus.Processing or CertificateRequestStatus.PendingRevocation;

    /// <summary>A status the request stays in until a person acts again: Issued, Rejected or Revoked.</summary>
    public static bool IsFinal(this CertificateRequestStatus status) =>
        status is CertificateRequestStatus.Issued or CertificateRequestStatus.Rejected or CertificateRequestStatus.Revoked;
}
