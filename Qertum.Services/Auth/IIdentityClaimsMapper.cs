using System.Security.Claims;

namespace Qertum.Services.Auth;

/// <summary>
/// Normalizes a <see cref="ClaimsPrincipal"/> from any OpenID Connect provider into the
/// role and scope values the application's permission model expects.
/// </summary>
public interface IIdentityClaimsMapper
{
    /// <summary>Roles carried by the principal, deduplicated case-insensitively.</summary>
    IReadOnlyCollection<string> GetRoles(ClaimsPrincipal principal);

    /// <summary>Scopes granted to the principal, deduplicated case-insensitively.</summary>
    IReadOnlyCollection<string> GetScopes(ClaimsPrincipal principal);

    /// <summary>Whether the principal holds the administrator role.</summary>
    bool IsAdmin(ClaimsPrincipal principal);

    /// <summary>
    /// Returns the best available display name for the principal, for audit logging and
    /// <c>RequestedBy</c> attribution. Prefers the configured <c>Identity:NameClaimType</c>,
    /// then falls back to <c>preferred_username</c>, then <c>name</c>, then <c>sub</c>.
    /// </summary>
    string GetName(ClaimsPrincipal principal);

    /// <summary>
    /// Returns the principal's stable subject identifier (the <c>sub</c> claim), or null when absent.
    /// Unlike <see cref="GetName"/> this is immutable in the issuer and therefore safe to use as an
    /// authorization key; it is stored as <c>CertificateRequest.RequestedBySubject</c>.
    /// </summary>
    string? GetSubject(ClaimsPrincipal principal);
}
