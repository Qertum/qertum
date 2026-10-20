using System.Security.Claims;
using Qertum.IdentityService.Services;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using FluentValidation;
using Qertum.IdentityService.Validators;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Account;

public sealed class ChangePasswordModel(
    JsonUserStore userStore,
    IPasswordAttemptLimiter attemptLimiter,
    IValidator<ChangePasswordModel.InputModel>? validator = null) : PageModel
{
    // Optional so code that constructs the page directly keeps compiling; DI supplies the registered one.
    private readonly IValidator<InputModel> _validator = validator ?? new ChangePasswordInputValidator();

    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>
    /// Renders the page in forced mode: no navigation away, explanatory banner, and a
    /// redirect to <see cref="ReturnUrl"/> on success. Presentation only, and client-supplied —
    /// it grants nothing, because a change still requires the current password. Enforcement is
    /// elsewhere and re-reads the flag on every request: <see cref="Filters.ForcedPasswordChangeFilter"/>
    /// gates every Razor Page except this one and sign-out, LoginModel diverts here after
    /// sign-in, and AuthorizationController blocks all four token-issuing paths.
    /// </summary>
    [BindProperty(SupportsGet = true)]
    public bool Forced { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? StatusMessage { get; set; }
    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        ModelState.AddValidationErrors(_validator.Validate(Input));
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please fill in all fields.";
            return Page();
        }

        if (Input.NewPassword != Input.ConfirmPassword)
        {
            ErrorMessage = "New password and confirmation do not match.";
            return Page();
        }

        var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(sub, out var id))
        {
            return Challenge();
        }

        var attemptNumber = await attemptLimiter.ReserveAsync(
            PasswordAttemptPurpose.ChangePassword, id.ToString(), cancellationToken);
        if (attemptNumber == 0)
        {
            ErrorMessage = "Too many failed attempts. Please wait before trying again.";
            return Page();
        }

        var result = await userStore.ChangePasswordAsync(id, Input.CurrentPassword!, Input.NewPassword!, cancellationToken);
        switch (result)
        {
            case JsonUserStore.ChangePasswordResult.Success:
                await attemptLimiter.ClearAsync(PasswordAttemptPurpose.ChangePassword,
                    id.ToString(), cancellationToken);

                // The change rotated the security stamp, which ends every session holding the old
                // one — this one included, unless it is re-issued with the new stamp here.
                var user = await userStore.FindActiveByIdAsync(id, cancellationToken);
                if (user is not null)
                {
                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        CookieSession.CreatePrincipal(user),
                        new AuthenticationProperties { IsPersistent = false });
                }
                if (Forced)
                {
                    // No root page is mapped, so the fallback goes to the profile page — the
                    // natural landing spot when there is no pending destination. The filter
                    // diverts with no returnUrl, which makes this the common path.
                    return !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)
                        ? Redirect(ReturnUrl)
                        : Redirect("/Account");
                }

                StatusMessage = "Password updated.";
                Input = new InputModel();
                ModelState.Clear();
                return Page();

            case JsonUserStore.ChangePasswordResult.CurrentPasswordIncorrect:
                ErrorMessage = attemptNumber >= PasswordAttemptLimiter.MaxAttempts
                    ? "Current password is incorrect. You have reached the maximum number of attempts."
                    : "Current password is incorrect.";
                return Page();

            case JsonUserStore.ChangePasswordResult.SameAsCurrent:
                await attemptLimiter.ClearAsync(PasswordAttemptPurpose.ChangePassword,
                    id.ToString(), cancellationToken);
                ErrorMessage = "Your new password must be different from your current password.";
                return Page();

            default:
                ErrorMessage = "Could not change password.";
                return Page();
        }
    }

    public sealed class InputModel
    {
        public string? CurrentPassword { get; set; }
        public string? NewPassword { get; set; }
        public string? ConfirmPassword { get; set; }
    }
}
