using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Acme;

/// <summary>
/// A pre-shared credential that authorises someone to create an ACME account (RFC 8555 §7.3.4).
/// Without external account binding, anyone who can reach <c>/acme/new-account</c> gets an account;
/// with it, an operator issues a key id and MAC key out of band and only holders of one can register.
/// </summary>
public sealed class AcmeExternalAccountKey
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>The key id the client puts in its binding JWS header. Given out with the MAC key.</summary>
    [MaxLength(64)]
    public string Kid { get; init; } = string.Empty;

    /// <summary>
    /// Base64url-encoded HMAC key. Encrypted at rest — it is a bearer credential: whoever holds it can
    /// register an ACME account against this CA.
    /// </summary>
    [MaxLength(512)]
    public string MacKey { get; init; } = string.Empty;

    /// <summary>Operator-facing label, e.g. the team or system the credential was issued to.</summary>
    [MaxLength(200)]
    public string Description { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// The account this credential registered, once it has been used. A credential binds to exactly
    /// one account: reuse against a second account key would let one leaked credential mint accounts
    /// indefinitely, which is the opposite of what the binding is for.
    /// </summary>
    public Guid? BoundAccountId { get; set; }

    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    public DateTime? BoundAtUtc { get; set; }
}
