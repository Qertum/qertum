using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Acme;

/// <summary>An ACME http-01 challenge used to prove control of a domain identifier.</summary>
public sealed class AcmeChallenge
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public Guid AuthorizationId { get; init; }
    public AcmeAuthorization Authorization { get; init; } = null!;

    /// <summary>"http-01" (the only supported type in phase 1)</summary>
    [MaxLength(32)]
    public string Type { get; init; } = "http-01";

    /// <summary>"pending" | "processing" | "valid" | "invalid"</summary>
    [MaxLength(32)]
    public string Status { get; set; } = "pending";

    /// <summary>Cryptographically random token (base64url, 32 bytes). Served at /.well-known/acme-challenge/{Token}.</summary>
    [MaxLength(128)]
    public string Token { get; init; } = string.Empty;

    public DateTime? ValidatedAtUtc { get; set; }

    /// <summary>RFC 7807 problem-detail JSON stored when validation fails.</summary>
    [MaxLength(4096)]
    public string? ErrorJson { get; set; }

    public int ValidationAttempts { get; set; }

    /// <summary>
    /// Earliest UTC time the next verification attempt may run. Default <see cref="DateTime.MinValue"/>
    /// means "due now", so a freshly triggered challenge is picked up on the next poll. A failed
    /// attempt pushes this into the future instead of the loop sleeping, so one unreachable domain
    /// cannot hold up verification of every other pending challenge.
    /// </summary>
    public DateTime NextAttemptAfterUtc { get; set; } = DateTime.MinValue;
}
