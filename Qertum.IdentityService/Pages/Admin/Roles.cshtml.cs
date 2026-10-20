using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin;

public sealed class RolesModel(
    UserAdministrationService admin,
    JsonRoleStore roleStore,
    JsonUserStore userStore,
    ILogger<RolesModel> logger) : PageModel
{
    [BindProperty]
    public string? Name { get; set; }

    [BindProperty]
    public string? Description { get; set; }

    [BindProperty]
    public string? NewName { get; set; }

    public IReadOnlyList<RoleRow> Rows { get; private set; } = [];

    public string? StatusMessage { get; private set; }

    public string? ErrorMessage { get; private set; }

    public sealed record RoleRow(RoleDefinition Role, int HolderCount);

    public Task OnGetAsync(CancellationToken cancellationToken) => LoadAsync(cancellationToken);

    public Task<IActionResult> OnPostCreateAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.CreateRoleAsync(actor, Name?.Trim() ?? string.Empty, Description?.Trim() ?? string.Empty, cancellationToken),
            "Role created.", "create role", cancellationToken);

    public Task<IActionResult> OnPostUpdateAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.UpdateRoleAsync(actor, Name ?? string.Empty, Description?.Trim() ?? string.Empty, cancellationToken),
            "Description saved.", "update role", cancellationToken);

    public Task<IActionResult> OnPostRenameAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.RenameRoleAsync(actor, Name ?? string.Empty, NewName?.Trim() ?? string.Empty, cancellationToken),
            "Role renamed. The CA keeps its permission grants under the old name — rename it on the CA's Roles & permissions page too.",
            "rename role", cancellationToken);

    public Task<IActionResult> OnPostDeleteAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.DeleteRoleAsync(actor, Name ?? string.Empty, cancellationToken),
            "Role deleted.", "delete role", cancellationToken);

    private async Task<IActionResult> RunAsync(
        Func<AdminActor, Task<AdminOutcome>> action, string successMessage, string actionName, CancellationToken cancellationToken)
    {
        try
        {
            var outcome = await action(AdminActor.From(User));
            if (outcome.Result == AdminResult.Success)
            {
                StatusMessage = successMessage;
                Name = null;
                Description = null;
                NewName = null;
                ModelState.Clear();
            }
            else
            {
                ErrorMessage = AdminMessages.For(outcome.Result);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Admin action {Action} failed.", actionName);
            ErrorMessage = AdminMessages.Unexpected;
        }

        await LoadAsync(cancellationToken);
        return Page();
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
        var roles = await roleStore.GetAllAsync(cancellationToken);
        var users = await userStore.GetAllAsync(cancellationToken);
        Rows = roles
            .Select(r => new RoleRow(r, users.Count(u => u.Roles.Contains(r.Name, StringComparer.OrdinalIgnoreCase))))
            .ToList();
    }
}
