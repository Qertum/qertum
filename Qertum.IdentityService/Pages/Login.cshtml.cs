using Qertum.IdentityService.Services;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using FluentValidation;
using Qertum.IdentityService.Validators;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages;

/// <summary>
/// Sign-in page. Attempt reservations are keyed by username, with the same response for known
/// and unknown usernames.
/// </summary>
public sealed class LoginModel(
    JsonUserStore userStore,
    IPasswordAttemptLimiter attemptLimiter,
    IIdentityAuditLog audit,
    IValidator<LoginModel.InputModel>? validator = null) : PageModel
{
    // Optional so code that constructs the page directly keeps compiling; DI supplies the registered one.
    private readonly IValidator<InputModel> _validator = validator ?? new LoginInputValidator();

    /// <summary>Password checks allowed per username inside <see cref="Window"/>.</summary>
    public const int MaxAttempts = PasswordAttemptLimiter.MaxAttempts;

    /// <summary>How long attempts are counted for, and so how long a throttle lasts.</summary>
    public static readonly TimeSpan Window = PasswordAttemptLimiter.LoginWindow;

    [BindProperty]
    public InputModel Input { get; set; } = new();

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        ModelState.AddValidationErrors(_validator.Validate(Input));
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please provide a username and password.";
            return Page();
        }

        if (await attemptLimiter.ReserveAsync(PasswordAttemptPurpose.Login, Input.Username!, cancellationToken) == 0)
        {
            // Same message as a wrong password: the limiter must not say which accounts exist.
            audit.Write(IdentityAuditActions.LoginThrottled, Input.Username!);
            ErrorMessage = "Invalid username or password.";
            return Page();
        }

        var user = await userStore.ValidateCredentialsAsync(Input.Username!, Input.Password!, cancellationToken);
        if (user is null)
        {
            ErrorMessage = "Invalid username or password.";
            return Page();
        }

        await attemptLimiter.ClearAsync(PasswordAttemptPurpose.Login, Input.Username!, cancellationToken);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            CookieSession.CreatePrincipal(user),
            new AuthenticationProperties { IsPersistent = false });

        var safeReturnUrl = !string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl)
            ? ReturnUrl
            : null;

        // The cookie is issued first on purpose: the change-password page needs an
        // authenticated identity to work against. The flag still blocks every token-issuing
        // path, so a cookie alone gets this user nothing else.
        if (user.MustChangePassword)
        {
            var forcedUrl = "/Account/ChangePassword?forced=true";
            if (safeReturnUrl is not null)
            {
                forcedUrl += "&returnUrl=" + Uri.EscapeDataString(safeReturnUrl);
            }

            return Redirect(forcedUrl);
        }

        return Redirect(safeReturnUrl ?? "/");
    }

    public sealed class InputModel
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }
}
