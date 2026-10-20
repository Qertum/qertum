using System.Security.Claims;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Qertum.IdentityService.Controllers;

public sealed class AuthorizationController(JsonUserStore userStore, JsonClientStore clientStore) : Controller
{
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var authenticate = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authenticate.Succeeded)
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = CurrentRequestUrl()
            }, CookieAuthenticationDefaults.AuthenticationScheme);
        }

        var (user, recovery) = await ResolveCookieUserAsync(authenticate);
        if (user is null)
        {
            return recovery!;
        }

        if (user.MustChangePassword)
        {
            return RedirectToForcedPasswordChange();
        }

        var identity = CreateUserIdentity(user);
        identity.SetScopes(request.GetScopes());
        identity.SetResources("qertum-api");

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType() || request.IsDeviceCodeGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal
                ?? throw new InvalidOperationException("The authorization grant principal is missing.");

            // Applies to all three user grants in this branch: an authorization code, device
            // code or refresh token minted before the flag was set would otherwise still be
            // redeemable for a full-lifetime access token without ever changing the password.
            // The subject is a user id for all three; client_credentials is handled separately
            // below (its subject is the client_id, and it never reaches here).
            var user = Guid.TryParse(principal.GetClaim(Claims.Subject), out var grantUserId)
                ? await userStore.FindActiveByIdAsync(grantUserId)
                : null;

            // A grant outlives the user it was issued to unless it is checked here: a refresh
            // token for a user since deleted from users.json or disabled would otherwise keep
            // minting access tokens until it expired.
            if (user is null)
            {
                return ForbidGrant("The account is no longer active.");
            }

            if (user.MustChangePassword)
            {
                return ForbidGrant("The password for this account must be changed before it can be used.");
            }

            // A grant issued before a password change carries the old stamp. Grants from before
            // stamps existed carry none, which matches a user who has not changed password since.
            var grantStamp = principal.GetClaim(StoredUser.SecurityStampClaimType) ?? string.Empty;
            if (!string.Equals(grantStamp, user.SecurityStamp, StringComparison.Ordinal))
            {
                return ForbidGrant("The password for this account has changed.");
            }

            // Rebuild the user's claims from the store rather than re-signing the grant's copy,
            // which would carry the roles the user had when the grant was first issued.
            ApplyUserClaims((ClaimsIdentity)principal.Identity!, user);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsClientCredentialsGrantType())
        {
            // For client credentials, create a machine-to-machine principal scoped to the client.
            var identity = new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.AddClaim(new Claim(Claims.Subject, request.ClientId!));
            identity.AddClaim(new Claim(Claims.ClientId, request.ClientId!));

            // Include any roles configured for this client so role-based policies work.
            var storedClient = clientStore.GetAll()
                .FirstOrDefault(c => c.ClientId == request.ClientId);
            foreach (var role in storedClient?.Roles ?? [])
            {
                identity.AddClaim(new Claim(Claims.Role, role).SetDestinations(Destinations.AccessToken));
            }

            identity.SetScopes(request.GetScopes());
            identity.SetResources("qertum-api");

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        throw new NotImplementedException($"The grant type '{request.GrantType}' is not supported.");
    }

    [HttpGet("~/connect/verify"), HttpPost("~/connect/verify")]
    public async Task<IActionResult> Verify()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var authenticate = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!authenticate.Succeeded)
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = CurrentRequestUrl()
            }, CookieAuthenticationDefaults.AuthenticationScheme);
        }

        // No user_code yet: send to the code-entry page.
        if (string.IsNullOrEmpty(request.UserCode))
            return Redirect("/device");

        // GET with user_code: show confirmation page.
        if (HttpMethods.IsGet(Request.Method))
        {
            var (user, recovery) = await ResolveCookieUserAsync(authenticate);
            if (user is null)
            {
                return recovery!;
            }

            if (user.MustChangePassword)
            {
                return RedirectToForcedPasswordChange();
            }

            return Content(DeviceConfirmationHtml(user.Username, request.UserCode), "text/html");
        }

        // POST: user denied — mark as access_denied and let the event handler show the result page.
        if (Request.Form.TryGetValue("deny", out var denyVal) && denyVal == "true")
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // POST: user approved — build identity and complete device authorization.
        var (confirmedUser, confirmRecovery) = await ResolveCookieUserAsync(authenticate);
        if (confirmedUser is null)
        {
            return confirmRecovery!;
        }

        if (confirmedUser.MustChangePassword)
        {
            return RedirectToForcedPasswordChange();
        }

        // The scopes belong to the device authorization request, which OpenIddict resolves from
        // the user_code. The verification request itself carries none, so reading them from
        // `request` granted no scopes at all — offline_access included, which is why the device
        // flow never returned a refresh token.
        var verification = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var identity = CreateUserIdentity(confirmedUser);
        identity.SetScopes(verification.Principal?.GetScopes() ?? request.GetScopes());
        identity.SetResources("qertum-api");

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static readonly string[] UserClaimTypes =
        [Claims.Name, Claims.PreferredUsername, Claims.GivenName, Claims.Email, Claims.Role];

    private static ClaimsIdentity CreateUserIdentity(StoredUser user)
    {
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.AddClaim(new Claim(Claims.Subject, user.Id.ToString()));
        // No destinations: OpenIddict keeps it inside codes and refresh tokens, never in an
        // access or identity token. Exchange compares it against the stored user.
        identity.AddClaim(new Claim(StoredUser.SecurityStampClaimType, user.SecurityStamp));
        ApplyUserClaims(identity, user);
        return identity;
    }

    /// <summary>
    /// Replaces the user-derived claims on <paramref name="identity"/> with the stored user's
    /// current values. Everything else — subject, scopes, resources and OpenIddict's own private
    /// claims such as the authorization id — is left as it is, so a refreshed grant stays linked
    /// to the authorization it came from and can still be revoked through it.
    /// </summary>
    private static void ApplyUserClaims(ClaimsIdentity identity, StoredUser user)
    {
        foreach (var claim in identity.Claims.Where(c => UserClaimTypes.Contains(c.Type)).ToList())
        {
            identity.RemoveClaim(claim);
        }

        AddUserClaim(identity, Claims.Name, user.Username);
        AddUserClaim(identity, Claims.PreferredUsername, user.Username);

        if (!string.IsNullOrWhiteSpace(user.DisplayName))
        {
            AddUserClaim(identity, Claims.GivenName, user.DisplayName);
        }
        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            AddUserClaim(identity, Claims.Email, user.Email);
        }
        foreach (var role in user.Roles)
        {
            AddUserClaim(identity, Claims.Role, role);
        }
    }

    private static void AddUserClaim(ClaimsIdentity identity, string type, string value) =>
        identity.AddClaim(new Claim(type, value).SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));

    private IActionResult ForbidGrant(string description) =>
        Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
            }));

    /// <summary>
    /// The current request reproduced as a local URL, so a redirect away from an OIDC endpoint
    /// can send the user back to finish the flow.
    /// </summary>
    private string CurrentRequestUrl() =>
        Request.PathBase + Request.Path +
        QueryString.Create(Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList());

    /// <summary>
    /// Sends a user whose password must change to the forced change-password page, carrying
    /// the current OIDC request as the return URL so the flow resumes after the change.
    /// </summary>
    private IActionResult RedirectToForcedPasswordChange() =>
        Redirect("/Account/ChangePassword?forced=true&returnUrl=" + Uri.EscapeDataString(CurrentRequestUrl()));

    /// <summary>
    /// Resolves the cookie principal to a stored user, or returns an action that recovers from a
    /// cookie naming a user who no longer exists — which happens whenever users.json is reset
    /// underneath a live session. Dropping the stale cookie and re-challenging lets the user log
    /// back in; throwing would strand them on a 500 until they cleared site data by hand.
    /// </summary>
    private async Task<(StoredUser? User, IActionResult? Recovery)> ResolveCookieUserAsync(
        AuthenticateResult authenticate)
    {
        var subject = authenticate.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (Guid.TryParse(subject, out var id) && await userStore.FindActiveByIdAsync(id) is { } user)
        {
            return (user, null);
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return (null, Challenge(
            new AuthenticationProperties { RedirectUri = CurrentRequestUrl() },
            CookieAuthenticationDefaults.AuthenticationScheme));
    }

    private static string DeviceConfirmationHtml(string username, string userCode) =>
        $$"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <title>Authorize Device · Qertum IDM</title>
            <link rel="stylesheet" href="/identity.css" />
        </head>
        <body class="centered">
            <main class="shell-main">
                <div class="card">
                    <a class="card-brand" href="/">
                        <span class="brand-mark" aria-hidden="true"></span>
                        <span class="brand-text">
                            <span class="brand-name">Custom<em>CA</em></span>
                            <span class="brand-sub">Identity</span>
                        </span>
                    </a>
                    <h1>Authorize <em>Device</em></h1>
                    <p class="card-sub">Signed in as <strong>{{username}}</strong>. Allow CLI access?</p>
                    <div class="field">
                        <label>Device Code</label>
                        <div class="readonly mono">{{userCode}}</div>
                    </div>
                    <form method="post" action="/connect/verify">
                        <input type="hidden" name="user_code" value="{{userCode}}" />
                        <button type="submit">
                            <span class="bi bi-check-circle"></span>
                            Allow Access
                        </button>
                    </form>
                    <form method="post" action="/connect/verify" style="margin-top:0.75rem">
                        <input type="hidden" name="user_code" value="{{userCode}}" />
                        <input type="hidden" name="deny" value="true" />
                        <button type="submit" class="button secondary" style="width:100%">Deny</button>
                    </form>
                </div>
            </main>
        </body>
        </html>
        """;

    [HttpGet("~/connect/logout"), HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo"), Produces("application/json")]
    public async Task<IActionResult> UserInfo()
    {
        var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
        if (principal is null)
        {
            return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = principal.GetClaim(Claims.Subject) ?? string.Empty
        };

        if (principal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = principal.GetClaim(Claims.Name) ?? string.Empty;
            claims[Claims.PreferredUsername] = principal.GetClaim(Claims.PreferredUsername) ?? string.Empty;
            claims[Claims.GivenName] = principal.GetClaim(Claims.GivenName) ?? string.Empty;
        }

        if (principal.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = principal.GetClaim(Claims.Email) ?? string.Empty;
        }

        if (principal.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = principal.GetClaims(Claims.Role);
        }

        return Ok(claims);
    }
}
