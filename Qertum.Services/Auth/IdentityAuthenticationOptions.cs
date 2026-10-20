namespace Qertum.Services.Auth;

/// <summary>
/// Configuration for validating bearer tokens issued by an OpenID Connect provider.
/// Bound from the "Identity" configuration section.
/// </summary>
public sealed class IdentityAuthenticationOptions
{
    public const string SectionName = "Identity";

    /// <summary>
    /// Absolute URL of the token issuer. Must match the "iss" claim in issued tokens.
    /// Its discovery document is fetched from {Authority}/.well-known/openid-configuration.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Expected "aud" claim value on access tokens.</summary>
    public string Audience { get; set; } = "qertum-api";

    /// <summary>
    /// Whether OIDC metadata must be retrieved over HTTPS. Forced to false in Development.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>Claim type carrying the display name of the authenticated user.</summary>
    public string NameClaimType { get; set; } = "preferred_username";

    /// <summary>
    /// Claim type carrying role values. Supports dotted paths into JSON-valued claims,
    /// for example "realm_access.roles" for Keycloak.
    /// </summary>
    public string RoleClaimType { get; set; } = "role";

    /// <summary>
    /// Claim type carrying granted scopes. Values may be repeated claims or a single
    /// space-delimited string.
    /// </summary>
    public string ScopeClaimType { get; set; } = "scope";

    /// <summary>Step-up (MFA and recent sign-in) requirements for sensitive operations. Off by default.</summary>
    public StepUpOptions StepUp { get; set; } = new();

    /// <summary>
    /// Validates the configuration and normalizes <see cref="Authority"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">Configuration is missing or inconsistent.</exception>
    public void Validate(bool isDevelopment)
    {
        // First, so a bad step-up setting fails start-up in Development too.
        StepUp.Validate();

        if (string.IsNullOrWhiteSpace(Authority))
        {
            throw new InvalidOperationException(
                "Identity:Authority is not configured. Set it to the absolute URL of the OpenID Connect issuer, " +
                "for example https://idp.example.");
        }

        if (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri))
        {
            throw new InvalidOperationException(
                $"Identity:Authority ('{Authority}') must be an absolute URL, for example https://idp.example.");
        }

        Authority = Authority.TrimEnd('/');

        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException(
                "Identity:Audience is not configured. It must match the 'aud' claim on access tokens.");
        }

        if (isDevelopment)
        {
            RequireHttpsMetadata = false;
            return;
        }

        if (authorityUri.Scheme != Uri.UriSchemeHttps && RequireHttpsMetadata)
        {
            throw new InvalidOperationException(
                $"Identity:Authority ('{Authority}') uses plain HTTP outside Development. " +
                "Use HTTPS, or set Identity:RequireHttpsMetadata to false to accept this deliberately.");
        }

        if (string.IsNullOrWhiteSpace(NameClaimType))
        {
            throw new InvalidOperationException("Identity:NameClaimType must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(RoleClaimType))
        {
            throw new InvalidOperationException("Identity:RoleClaimType must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(ScopeClaimType))
        {
            throw new InvalidOperationException("Identity:ScopeClaimType must not be empty.");
        }
    }
}
