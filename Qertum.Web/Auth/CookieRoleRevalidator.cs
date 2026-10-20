using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Qertum.Services;

namespace Qertum.Web.Auth;

public sealed class RoleRevalidationOptions
{
    public const string SectionName = "Authentication:RoleRevalidation";

    /// <summary>How long the cookie's roles are trusted before the IdP is asked again.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>
/// Keeps the Web cookie's roles in step with the IdP.
/// <para>
/// The cookie copies roles from sign-in and slides for eight hours, so without this a removed
/// <c>admin</c> role kept opening Settings and Webhooks until the cookie expired. Once
/// <see cref="RoleRevalidationOptions.Interval"/> has passed, the next request redeems the
/// session's refresh token — which the IdP rebuilds from its user store and refuses for a deleted
/// or disabled user — and reads <c>userinfo</c> with the new access token. Refused: the session
/// ends. Accepted: the user claims are replaced and the rotated tokens are written back.
/// </para>
/// <para>
/// An unreachable IdP keeps the current principal and tries again on a later request; an IdP
/// outage should not sign everyone out. Only HTTP requests pass through here, so an already open
/// Blazor circuit keeps its authentication state until it reconnects.
/// </para>
/// </summary>
public sealed class CookieRoleRevalidator(
    OidcTokenClient tokenClient,
    IMeAccess meAccess,
    TimeProvider timeProvider,
    IOptions<RoleRevalidationOptions> options,
    ILogger<CookieRoleRevalidator> logger)
{
    public const string CheckedAtItem = ".roles_checked_at";

    /// <summary>
    /// Stamps a new session so revalidation does not run on the request right after sign-in, and
    /// reads the caller's permissions once so a fresh session is gated before the first revalidation.
    /// </summary>
    public async Task OnSigningInAsync(CookieSigningInContext context)
    {
        if (!context.Properties.Items.ContainsKey(CheckedAtItem))
            Stamp(context.Properties);

        var accessToken = context.Properties.GetTokenValue("access_token");
        if (string.IsNullOrEmpty(accessToken) || context.Principal?.Identity is not ClaimsIdentity identity)
            return;

        var access = await meAccess.GetAsync(accessToken, context.HttpContext.RequestAborted);
        if (access.Access is not null)
            context.Principal = new ClaimsPrincipal(ReplacePermissionClaims(identity, access.Access));
    }

    public async Task ValidatePrincipalAsync(CookieValidatePrincipalContext context)
    {
        if (context.Principal?.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
            return;

        // A cookie cannot be rewritten on a WebSocket upgrade, and rotated tokens that never reach
        // the browser would leave it holding a redeemed refresh token.
        if (context.HttpContext.WebSockets.IsWebSocketRequest)
            return;

        if (!IsDue(context.Properties))
            return;

        var cancellationToken = context.HttpContext.RequestAborted;
        var refreshToken = context.Properties.GetTokenValue("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.LogWarning("Session has no refresh token, so its roles cannot be revalidated; signing out.");
            await RejectAsync(context);
            return;
        }

        var refreshed = await tokenClient.RefreshAsync(refreshToken, cancellationToken);
        switch (refreshed.Outcome)
        {
            case OidcCallOutcome.Rejected:
                logger.LogInformation("IdP refused the session's refresh token; signing out.");
                await RejectAsync(context);
                return;
            case OidcCallOutcome.Unavailable:
                logger.LogWarning("IdP unavailable; keeping the current roles until a later request.");
                return;
        }

        // The old refresh token is spent from here on, so the new tokens are written back even if
        // userinfo fails below.
        StoreTokens(context.Properties, refreshed);
        context.ShouldRenew = true;

        var userInfo = await tokenClient.GetUserInfoAsync(refreshed.AccessToken!, cancellationToken);
        switch (userInfo.Outcome)
        {
            case OidcCallOutcome.Rejected:
                logger.LogInformation("IdP refused userinfo for a refreshed session; signing out.");
                await RejectAsync(context);
                return;
            case OidcCallOutcome.Unavailable:
                logger.LogWarning("userinfo unavailable; keeping the current roles until a later request.");
                return;
        }

        var identityWithRoles = ReplaceUserClaims(identity, userInfo.Claims);
        var access = await meAccess.GetAsync(refreshed.AccessToken!, cancellationToken);
        if (access.Outcome == OidcCallOutcome.Rejected)
        {
            logger.LogInformation("API refused the refreshed session; signing out.");
            await RejectAsync(context);
            return;
        }

        // Unavailable: keep whatever permission claims the cookie already carries.
        context.ReplacePrincipal(new ClaimsPrincipal(
            access.Access is null ? identityWithRoles : ReplacePermissionClaims(identityWithRoles, access.Access)));
        Stamp(context.Properties);
    }

    private bool IsDue(AuthenticationProperties properties)
    {
        if (!properties.Items.TryGetValue(CheckedAtItem, out var value) ||
            !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var checkedAt))
        {
            return true;
        }

        return timeProvider.GetUtcNow() - checkedAt >= options.Value.Interval;
    }

    private void Stamp(AuthenticationProperties properties) =>
        properties.Items[CheckedAtItem] = timeProvider.GetUtcNow().ToString("o", CultureInfo.InvariantCulture);

    private void StoreTokens(AuthenticationProperties properties, TokenRefreshResult refreshed)
    {
        var tokens = properties.GetTokens().ToDictionary(t => t.Name, t => t.Value, StringComparer.Ordinal);
        tokens["access_token"] = refreshed.AccessToken!;
        if (!string.IsNullOrEmpty(refreshed.RefreshToken))
            tokens["refresh_token"] = refreshed.RefreshToken;
        if (refreshed.ExpiresIn is { } expiresIn)
            tokens["expires_at"] = timeProvider.GetUtcNow().AddSeconds(expiresIn).ToString("o", CultureInfo.InvariantCulture);

        properties.StoreTokens(tokens.Select(t => new AuthenticationToken { Name = t.Key, Value = t.Value }));
    }

    private static ClaimsIdentity ReplacePermissionClaims(ClaimsIdentity current, MyAccessResponse access)
    {
        var claims = current.Claims
            .Where(c => c.Type != QertumWebClaims.Permission)
            .Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer))
            .Concat(access.Permissions.Where(p => p.Granted).Select(p => new Claim(QertumWebClaims.Permission, p.Name)));

        return new ClaimsIdentity(claims, current.AuthenticationType, current.NameClaimType, current.RoleClaimType);
    }

    private static ClaimsIdentity ReplaceUserClaims(ClaimsIdentity current, IReadOnlyList<Claim> userClaims)
    {
        var claims = current.Claims
            .Where(c => !OidcTokenClient.UserInfoClaimTypes.Contains(c.Type))
            .Select(c => new Claim(c.Type, c.Value, c.ValueType, c.Issuer, c.OriginalIssuer))
            .Concat(userClaims);

        return new ClaimsIdentity(claims, current.AuthenticationType, current.NameClaimType, current.RoleClaimType);
    }

    private static async Task RejectAsync(CookieValidatePrincipalContext context)
    {
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }
}
