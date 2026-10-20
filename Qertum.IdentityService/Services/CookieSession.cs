using System.Security.Claims;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Qertum.IdentityService.Services;

/// <summary>
/// Builds the IdP's cookie principal and keeps it in step with <c>users.json</c>.
/// <para>
/// The cookie copies roles at sign-in and lives for eight sliding hours, so without
/// <see cref="ValidateAsync"/> a removed <c>admin</c> role kept reaching the admin user pages and a
/// deleted or disabled user kept a working session until the cookie expired. Every
/// authenticated request now re-reads the user: gone or disabled ends the session, changed
/// roles are swapped into the principal on the spot, and a session
/// from before a password change (a stale <see cref="StoredUser.SecurityStamp"/>) ends.
/// </para>
/// </summary>
public static class CookieSession
{
    public static ClaimsPrincipal CreatePrincipal(StoredUser user)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim(StoredUser.SecurityStampClaimType, user.SecurityStamp));
        foreach (var role in user.Roles)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        return new ClaimsPrincipal(identity);
    }

    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var userStore = context.HttpContext.RequestServices.GetRequiredService<JsonUserStore>();
        var subject = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var user = Guid.TryParse(subject, out var id)
            ? await userStore.FindActiveByIdAsync(id, context.HttpContext.RequestAborted)
            : null;

        // A stamp that no longer matches is a session from before a password change.
        var cookieStamp = context.Principal?.FindFirst(StoredUser.SecurityStampClaimType)?.Value ?? string.Empty;
        if (user is null || !string.Equals(cookieStamp, user.SecurityStamp, StringComparison.Ordinal))
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return;
        }

        var cookieRoles = context.Principal!.FindAll(ClaimTypes.Role).Select(c => c.Value).Order(StringComparer.Ordinal);
        var storedRoles = user.Roles.Order(StringComparer.Ordinal);
        if (cookieRoles.SequenceEqual(storedRoles, StringComparer.Ordinal) &&
            context.Principal.Identity?.Name == user.Username)
        {
            return;
        }

        context.ReplacePrincipal(CreatePrincipal(user));
        context.ShouldRenew = true;
    }
}
