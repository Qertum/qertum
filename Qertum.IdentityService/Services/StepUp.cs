using System.Globalization;
using Microsoft.AspNetCore.Authentication;

namespace Qertum.IdentityService.Services;

/// <summary>
/// Time-boxed re-authentication for the admin pages. The timestamp lives in the IdP auth cookie's
/// properties, which are data-protected (unforgeable) and survive restarts and multiple instances.
/// <c>CookieSession.ValidateAsync</c> uses ReplacePrincipal, which keeps properties, so role
/// revalidation does not clear it; a password change re-issues the cookie without it.
/// </summary>
public static class StepUp
{
    public const string ItemKey = ".stepup_at";
    public const string ConfirmPath = "/Admin/Confirm";
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static bool IsFresh(AuthenticationProperties? properties, DateTimeOffset now)
    {
        if (properties is null || !properties.Items.TryGetValue(ItemKey, out var raw) || raw is null)
        {
            return false;
        }

        if (!DateTimeOffset.TryParseExact(raw, "O", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var confirmedAt))
        {
            return false;
        }

        var age = now - confirmedAt;
        return age >= TimeSpan.Zero && age < Window;
    }

    public static void Stamp(AuthenticationProperties properties, DateTimeOffset now) =>
        properties.Items[ItemKey] = now.ToString("O", CultureInfo.InvariantCulture);
}
