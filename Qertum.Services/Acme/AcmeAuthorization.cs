using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Acme;

/// <summary>An ACME authorization proving control of a single identifier (domain).</summary>
public sealed class AcmeAuthorization
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public Guid OrderId { get; init; }
    public AcmeOrder Order { get; init; } = null!;

    /// <summary>"dns" (the only supported type in phase 1)</summary>
    [MaxLength(32)]
    public string IdentifierType { get; init; } = "dns";

    [MaxLength(253)]
    public string IdentifierValue { get; init; } = string.Empty;

    /// <summary>
    /// True when this authorization was created for a wildcard identifier. RFC 8555 §7.1.4 stores
    /// the *base* name in <see cref="IdentifierValue"/> and reports the wildcard separately, so
    /// without this flag an order naming both "example.com" and "*.example.com" produces two rows
    /// that cannot be told apart.
    /// </summary>
    public bool Wildcard { get; init; }

    /// <summary>"pending" | "valid" | "invalid" | "expired" | "deactivated" | "revoked"</summary>
    [MaxLength(32)]
    public string Status { get; set; } = "pending";

    public DateTime ExpiresAtUtc { get; init; }

    public ICollection<AcmeChallenge> Challenges { get; init; } = [];
}
