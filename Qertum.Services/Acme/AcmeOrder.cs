using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Acme;

/// <summary>An ACME certificate order, created by POST /acme/new-order.</summary>
public sealed class AcmeOrder
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public Guid AccountId { get; init; }
    public AcmeAccount Account { get; init; } = null!;

    /// <summary>"pending" | "ready" | "processing" | "valid" | "invalid"</summary>
    [MaxLength(32)]
    public string Status { get; set; } = "pending";

    /// <summary>JSON array of identifier objects: [{"type":"dns","value":"example.com"}]</summary>
    [MaxLength(4096)]
    public string IdentifiersJson { get; init; } = "[]";

    public DateTime? NotBefore { get; init; }
    public DateTime? NotAfter { get; init; }

    /// <summary>When the order resource itself expires (RFC 8555 §7.4).</summary>
    public DateTime ExpiresAtUtc { get; init; }

    /// <summary>FK to the CertificateRequest created at finalize time. Null until finalized.</summary>
    public Guid? CertificateRequestId { get; set; }

    /// <summary>Full PEM chain (leaf + CA) stored once the underlying CertificateRequest is Issued.</summary>
    [MaxLength(16384)]
    public string? CertificatePem { get; set; }

    /// <summary>DER base64url CSR submitted at finalize time.</summary>
    [MaxLength(8192)]
    public string? CsrPem { get; set; }

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    public ICollection<AcmeAuthorization> Authorizations { get; init; } = [];
}
