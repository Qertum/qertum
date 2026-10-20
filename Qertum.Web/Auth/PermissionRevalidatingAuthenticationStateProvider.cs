using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.Extensions.Options;

namespace Qertum.Web.Auth;

/// <summary>
/// Re-reads the caller's access inside the circuit, because the cookie's revalidation only runs on
/// HTTP requests. A refusal ends the circuit's authentication; an unreachable API keeps the current
/// principal, matching <see cref="CookieRoleRevalidator"/>.
/// </summary>
public sealed class PermissionRevalidatingAuthenticationStateProvider(
    IMeAccess meAccess,
    ICircuitTokens tokens,
    IOptions<RoleRevalidationOptions> options,
    ILoggerFactory loggerFactory,
    ILogger<PermissionRevalidatingAuthenticationStateProvider> logger)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    /// <summary>The principal produced by the last successful revalidation; null when nothing changed.</summary>
    public ClaimsPrincipal? LastPrincipal { get; private set; }

    /// <inheritdoc />
    protected override TimeSpan RevalidationInterval => options.Value.Interval;

    /// <summary>Test seam: runs one revalidation pass.</summary>
    public Task<bool> RevalidateForTestAsync(AuthenticationState state, CancellationToken cancellationToken)
        => ValidateAuthenticationStateAsync(state, cancellationToken);

    /// <inheritdoc />
    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        if (authenticationState.User.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
            return false;

        var token = await tokens.GetAccessTokenAsync(cancellationToken);
        if (string.IsNullOrEmpty(token))
            return false;

        var access = await meAccess.GetAsync(token, cancellationToken);
        switch (access.Outcome)
        {
            case OidcCallOutcome.Rejected:
                logger.LogInformation("API refused this circuit's session; ending its authentication.");
                return false;
            case OidcCallOutcome.Unavailable:
                logger.LogWarning("API unavailable; keeping the circuit's current claims.");
                return true;
        }

        var refreshed = new ClaimsIdentity(
            identity.Claims
                .Where(c => c.Type != QertumWebClaims.Permission && c.Type != identity.RoleClaimType)
                .Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer))
                .Concat(access.Access!.Roles.Select(r => new Claim(identity.RoleClaimType, r)))
                .Concat(access.Access.Permissions.Where(p => p.Granted).Select(p => new Claim(QertumWebClaims.Permission, p.Name))),
            identity.AuthenticationType, identity.NameClaimType, identity.RoleClaimType);

        LastPrincipal = new ClaimsPrincipal(refreshed);
        SetAuthenticationState(Task.FromResult(new AuthenticationState(LastPrincipal)));
        return true;
    }
}
