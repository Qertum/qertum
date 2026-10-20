using System.Security.Claims;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;
using FluentValidation;
using Qertum.IdentityService.Validators;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Account;

public sealed class IndexModel(
    JsonUserStore userStore,
    JsonRoleStore roleStore,
    IValidator<IndexModel.InputModel>? validator = null) : PageModel
{
    // Optional so code that constructs the page directly keeps compiling; DI supplies the registered one.
    private readonly IValidator<InputModel> _validator = validator ?? new ProfileInputValidator();

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string Username { get; set; } = string.Empty;
    public IReadOnlyList<string> Roles { get; set; } = Array.Empty<string>();

    public IReadOnlyDictionary<string, string> RoleDescriptions { get; set; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string? DescriptionFor(string role) =>
        RoleDescriptions.TryGetValue(role, out var description) && !string.IsNullOrEmpty(description) ? description : null;

    public string? StatusMessage { get; set; }
    public string? ErrorMessage { get; set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        var user = await LoadCurrentAsync(cancellationToken);
        if (user is null)
        {
            return Challenge();
        }

        Username = user.Username;
        Roles = user.Roles;
        RoleDescriptions = (await roleStore.GetAllAsync(cancellationToken))
            .ToDictionary(r => r.Name, r => r.Description, StringComparer.OrdinalIgnoreCase);
        Input = new InputModel { DisplayName = user.DisplayName, Email = user.Email };
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        var user = await LoadCurrentAsync(cancellationToken);
        if (user is null)
        {
            return Challenge();
        }

        Username = user.Username;
        Roles = user.Roles;
        RoleDescriptions = (await roleStore.GetAllAsync(cancellationToken))
            .ToDictionary(r => r.Name, r => r.Description, StringComparer.OrdinalIgnoreCase);

        ModelState.AddValidationErrors(_validator.Validate(Input));
        if (!ModelState.IsValid)
        {
            ErrorMessage = "Please provide valid values.";
            return Page();
        }

        await userStore.UpdateProfileAsync(user.Id, Input.DisplayName ?? string.Empty, Input.Email ?? string.Empty, cancellationToken);
        StatusMessage = "Profile updated.";
        return Page();
    }

    private async Task<StoredUser?> LoadCurrentAsync(CancellationToken cancellationToken)
    {
        var sub = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(sub, out var id))
        {
            return null;
        }
        return await userStore.FindByIdAsync(id, cancellationToken);
    }

    public sealed class InputModel
    {
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
    }
}
