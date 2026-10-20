using System.Text.Json.Serialization;
using System.ComponentModel.DataAnnotations;

namespace Qertum.Services;

/// <summary>Which classical family an exception admits.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PqcExceptionFamily
{
    /// <summary>RSA keys.</summary>
    Rsa,
    /// <summary>ECDSA keys (P-256 and P-384).</summary>
    Ecdsa
}

/// <summary>
/// A time-limited, audited permission for one identity to keep using a classical key under a template
/// at PQC stage <see cref="PqcStage.Pilot"/> or <see cref="PqcStage.Enforce"/>. Immutable except for
/// revocation. Never applies to CA keys.
/// </summary>
public sealed class PqcException
{
    /// <summary>Primary key.</summary>
    public PqcExceptionId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>Template <c>TypeKey</c> the exception applies to.</summary>
    [Required, MaxLength(50)]
    public string TemplateTypeKey { get; set; } = "";

    /// <summary>Exact DNS name or DNS suffix; matches like the policy engine's allowed DNS suffixes.</summary>
    [Required, MaxLength(253)]
    public string NamePattern { get; set; } = "";

    /// <summary>The classical family admitted.</summary>
    public PqcExceptionFamily Family { get; set; }

    /// <summary>Instant after which the exception no longer applies (strictly greater than now is active).</summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Why the exception was granted.</summary>
    [Required, MaxLength(500)]
    public string Reason { get; set; } = "";

    /// <summary>Stable <c>sub</c> of the granting admin.</summary>
    [MaxLength(200)]
    public string? GrantedBySubject { get; set; }

    /// <summary>Display name of the granting admin.</summary>
    [Required, MaxLength(200)]
    public string GrantedBy { get; set; } = "";

    /// <summary>When it was granted.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Display name of the revoking admin; null while not revoked.</summary>
    [MaxLength(200)]
    public string? RevokedBy { get; set; }

    /// <summary>When it was revoked; null while not revoked.</summary>
    public DateTime? RevokedAtUtc { get; set; }
}

/// <summary>Body of <c>POST /v1/pqc-exceptions</c>.</summary>
public sealed class CreatePqcExceptionRequest
{
    /// <summary>Template <c>TypeKey</c> the exception applies to; must exist.</summary>
    public string TemplateTypeKey { get; set; } = "";

    /// <summary>Exact DNS name or DNS suffix. Wildcards and IP addresses are not accepted.</summary>
    public string NamePattern { get; set; } = "";

    /// <summary>The classical family admitted.</summary>
    public PqcExceptionFamily Family { get; set; }

    /// <summary>When the exception stops applying. Must be in the future and within <c>PqcExceptions:MaxDays</c>.</summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Why the exception is granted (at most 500 characters).</summary>
    public string Reason { get; set; } = "";
}

/// <summary>A PQC exception as returned by the API.</summary>
public sealed class PqcExceptionResponse
{
    /// <summary>Exception id.</summary>
    public PqcExceptionId Id { get; set; }

    /// <summary>Template <c>TypeKey</c> the exception applies to.</summary>
    public string TemplateTypeKey { get; set; } = "";

    /// <summary>Normalized DNS name or suffix.</summary>
    public string NamePattern { get; set; } = "";

    /// <summary>The classical family admitted.</summary>
    public PqcExceptionFamily Family { get; set; }

    /// <summary>When the exception stops applying.</summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Why it was granted.</summary>
    public string Reason { get; set; } = "";

    /// <summary>Display name of the granting admin.</summary>
    public string GrantedBy { get; set; } = "";

    /// <summary>When it was granted.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Display name of the revoking admin; null while not revoked.</summary>
    public string? RevokedBy { get; set; }

    /// <summary>When it was revoked; null while not revoked.</summary>
    public DateTime? RevokedAtUtc { get; set; }

    /// <summary>Not revoked and not yet expired, judged by the server clock when the response was built.</summary>
    public bool IsActive { get; set; }
}
