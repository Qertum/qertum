using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Stores;
using FluentValidation;
using Qertum.IdentityService.Validators;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin.Users;

public sealed class NewModel(
    UserAdministrationService admin,
    JsonRoleStore roleStore,
    ILogger<NewModel> logger,
    IValidator<NewModel.InputModel>? validator = null) : PageModel
{
    // Optional so code that constructs the page directly keeps compiling; DI supplies the registered one.
    private readonly IValidator<InputModel> _validator = validator ?? new NewUserInputValidator();

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IReadOnlyList<RoleDefinition> Catalog { get; private set; } = [];

    public string? ErrorMessage { get; private set; }

    public string? CreatedUsername { get; private set; }

    /// <summary>Rendered once in this response only; never put in TempData, a query string or a log.</summary>
    public string? OneTimePassword { get; private set; }

    public async Task OnGetAsync(CancellationToken cancellationToken) =>
        Catalog = await roleStore.GetAllAsync(cancellationToken);

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        Catalog = await roleStore.GetAllAsync(cancellationToken);
        ModelState.AddValidationErrors(_validator.Validate(Input));
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please correct the highlighted fields.";
            return Page();
        }

        AdminOutcome outcome;
        try
        {
            outcome = await admin.CreateUserAsync(
                AdminActor.From(User),
                Input.Username!.Trim(),
                Input.Email!.Trim(),
                Input.DisplayName?.Trim() ?? string.Empty,
                Input.Roles,
                cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Creating a user failed.");
            ErrorMessage = AdminMessages.Unexpected;
            return Page();
        }

        if (!outcome.Succeeded)
        {
            ErrorMessage = AdminMessages.For(outcome.Result);
            return Page();
        }

        Response.Headers.CacheControl = "no-store";
        CreatedUsername = Input.Username!.Trim();
        OneTimePassword = outcome.OneTimePassword;
        Input = new InputModel();
        ModelState.Clear();
        return Page();
    }

    public sealed class InputModel
    {
        public string? Username { get; set; }
        public string? DisplayName { get; set; }
        public string? Email { get; set; }

        public List<string> Roles { get; set; } = [];
    }
}
