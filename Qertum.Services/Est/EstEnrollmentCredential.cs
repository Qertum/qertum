using System.ComponentModel.DataAnnotations;

namespace Qertum.Services.Est;

/// <summary>
/// A bootstrap credential authorising HTTP Basic-authenticated EST enrollment (RFC 7030 §3.3.1,
/// <c>/simpleenroll</c>). Unlike ACME's <see cref="Acme.AcmeExternalAccountKey"/> (a reversibly
/// encrypted HMAC key, because HMAC verification needs the symmetric key back), this is a one-way
/// hash: HTTP Basic only ever needs to verify a password, never recover it.
/// </summary>
public sealed class EstEnrollmentCredential
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>The username the client sends in the HTTP Basic <c>Authorization</c> header.</summary>
    [MaxLength(200)]
    public string Username { get; init; } = string.Empty;

    /// <summary>PBKDF2 hash of the password, via <see cref="Microsoft.AspNetCore.Identity.PasswordHasher{TUser}"/>.</summary>
    [MaxLength(512)]
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Operator-facing label, e.g. the device or fleet the credential was issued to.</summary>
    [MaxLength(200)]
    public string Description { get; set; } = string.Empty;

    public bool IsEnabled { get; set; } = true;

    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}
