using System.Security.Claims;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Account;

[AllowAnonymous]
public sealed class LogoutModel(JsonUserStore userStore) : PageModel
{
    public bool IsSignedOut { get; private set; }

    /// <summary>
    /// Whether the signed-in user still owes a password change. This page is exempt from
    /// <see cref="Filters.ForcedPasswordChangeFilter"/> so a stuck user can always leave, which
    /// means it is the one authenticated page such a user can reach — so it must not offer
    /// navigation the filter would only bounce back.
    /// </summary>
    public bool MustChangePassword { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        IsSignedOut = User.Identity?.IsAuthenticated != true;
        if (IsSignedOut)
        {
            return;
        }

        MustChangePassword =
            Guid.TryParse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) &&
            await userStore.RequiresPasswordChangeAsync(id, cancellationToken);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/Account/Logout");
    }
}
