using System.Security.Claims;
using Qertum.IdentityService.Services;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin;

public sealed class ConfirmModel(
    JsonUserStore userStore,
    IPasswordAttemptLimiter attemptLimiter,
    IIdentityAuditLog audit,
    TimeProvider timeProvider) : PageModel
{
    [BindProperty]
    public string? Password { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>Set by <c>StepUpFilter</c> when a form was posted after the window had lapsed.</summary>
    [BindProperty(SupportsGet = true)]
    public bool Expired { get; set; }

    public string? ErrorMessage { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id))
        {
            return Challenge();
        }

        if (await attemptLimiter.ReserveAsync(PasswordAttemptPurpose.StepUp, id.ToString(), cancellationToken) == 0)
        {
            ErrorMessage = "Too many failed attempts. Please wait before trying again.";
            return Page();
        }

        if (string.IsNullOrEmpty(Password) || !await userStore.VerifyPasswordAsync(id, Password, cancellationToken))
        {
            audit.Write(IdentityAuditActions.StepUpFailed, User.Identity?.Name ?? string.Empty, id);
            ErrorMessage = "Password is incorrect.";
            return Page();
        }

        await attemptLimiter.ClearAsync(PasswordAttemptPurpose.StepUp, id.ToString(), cancellationToken);

        // Re-issue the same ticket with the timestamp added; persistence and expiry carry over.
        var auth = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!auth.Succeeded || auth.Principal is null || auth.Properties is null)
        {
            return Challenge();
        }

        StepUp.Stamp(auth.Properties, timeProvider.GetUtcNow());
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, auth.Principal, auth.Properties);

        return Redirect(!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/Admin/Users");
    }
}
