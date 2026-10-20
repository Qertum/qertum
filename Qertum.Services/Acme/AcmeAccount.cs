using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Acme;

/// <summary>An ACME client account identified by a JWK key pair.</summary>
public sealed class AcmeAccount
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>
    /// SHA-256 thumbprint of the account public key (RFC 7638), base64url-encoded. Used as stable
    /// account identifier. Settable because key rollover (<c>POST /acme/key-change</c>) replaces it
    /// in place — the account keeps its id and its orders, only the key it is authenticated by moves.
    /// </summary>
    [MaxLength(64)]
    public string JwkThumbprint { get; set; } = string.Empty;

    /// <summary>Full JWK JSON of the account public key, for signature verification. Replaced by key rollover.</summary>
    [MaxLength(4096)]
    public string PublicKeyJwk { get; set; } = string.Empty;

    /// <summary>
    /// "valid" | "deactivated" | "revoked". Settable because an account holder may deactivate their
    /// own account (RFC 8555 §7.3.6); that move is one-way, which the endpoint enforces.
    /// </summary>
    [MaxLength(32)]
    public string Status { get; set; } = "valid";

    public bool TermsOfServiceAgreed { get; init; }

    /// <summary>
    /// JSON array of contact URIs, e.g. ["mailto:admin@example.com"]. Settable because account update
    /// (RFC 8555 §7.3.2) replaces the list wholesale — the field is the client's to maintain.
    /// </summary>
    [MaxLength(2048)]
    public string? ContactsJson { get; set; }

    /// <summary>
    /// The external account credential this account was registered with, when binding is in use
    /// (RFC 8555 §7.3.4). Null for accounts created while binding was not required.
    /// </summary>
    [MaxLength(64)]
    public string? ExternalAccountKid { get; init; }

    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    public ICollection<AcmeOrder> Orders { get; init; } = [];
}
