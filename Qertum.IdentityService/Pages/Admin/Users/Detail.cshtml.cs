using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin.Users;

public sealed class DetailModel(
    UserAdministrationService admin,
    JsonUserStore userStore,
    JsonRoleStore roleStore,
    ILogger<DetailModel> logger) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public Guid Id { get; set; }

    [BindProperty]
    public List<string> Roles { get; set; } = [];

    public StoredUser? Target { get; private set; }

    public IReadOnlyList<RoleDefinition> Catalog { get; private set; } = [];

    public IReadOnlyList<string> RolesMissingFromCatalog { get; private set; } = [];

    public bool IsSelf { get; private set; }

    public bool ConfirmingDelete { get; private set; }

    public string? StatusMessage { get; private set; }

    public string? ErrorMessage { get; private set; }

    /// <summary>Rendered once in this response only; never put in TempData, a query string or a log.</summary>
    public string? OneTimePassword { get; private set; }

    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken) =>
        await LoadAsync(cancellationToken) ? Page() : NotFound();

    public Task<IActionResult> OnPostRolesAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.SetRolesAsync(actor, Id, Roles, cancellationToken), "Roles updated.", "set roles", cancellationToken);

    public Task<IActionResult> OnPostDisableAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.SetDisabledAsync(actor, Id, true, cancellationToken),
            "Account disabled. Its sessions end on their next request.", "disable", cancellationToken);

    public Task<IActionResult> OnPostEnableAsync(CancellationToken cancellationToken) =>
        RunAsync(actor => admin.SetDisabledAsync(actor, Id, false, cancellationToken), "Account enabled.", "enable", cancellationToken);

    public async Task<IActionResult> OnPostResetPasswordAsync(CancellationToken cancellationToken)
    {
        var outcome = await ExecuteAsync(actor => admin.ResetPasswordAsync(actor, Id, cancellationToken), "reset password");
        if (outcome is { Result: AdminResult.Success })
        {
            Response.Headers.CacheControl = "no-store";
            OneTimePassword = outcome.OneTimePassword;
            StatusMessage = "Password reset. Every existing session and grant for this user has ended.";
        }

        return await LoadAsync(cancellationToken) ? Page() : NotFound();
    }

    public async Task<IActionResult> OnPostConfirmDeleteAsync(CancellationToken cancellationToken)
    {
        ConfirmingDelete = true;
        return await LoadAsync(cancellationToken) ? Page() : NotFound();
    }

    public async Task<IActionResult> OnPostDeleteAsync(CancellationToken cancellationToken)
    {
        var outcome = await ExecuteAsync(actor => admin.DeleteUserAsync(actor, Id, cancellationToken), "delete");
        if (outcome is { Result: AdminResult.Success })
        {
            return Redirect("/Admin/Users");
        }

        // Refused: show the page again. Deleted with incomplete revocation: the user is gone, so the
        // page renders only the message (Target stays null).
        if (outcome is { Result: AdminResult.DeletedButRevocationIncomplete })
        {
            return Page();
        }

        return await LoadAsync(cancellationToken) ? Page() : NotFound();
    }

    private async Task<IActionResult> RunAsync(
        Func<AdminActor, Task<AdminOutcome>> action, string successMessage, string actionName, CancellationToken cancellationToken)
    {
        var outcome = await ExecuteAsync(action, actionName);
        if (outcome is { Result: AdminResult.Success })
        {
            StatusMessage = successMessage;
        }

        return await LoadAsync(cancellationToken) ? Page() : NotFound();
    }

    /// <summary>Runs one admin action; sets <see cref="ErrorMessage"/> from fixed text only.</summary>
    private async Task<AdminOutcome?> ExecuteAsync(Func<AdminActor, Task<AdminOutcome>> action, string actionName)
    {
        try
        {
            var outcome = await action(AdminActor.From(User));
            if (outcome.Result != AdminResult.Success)
            {
                ErrorMessage = AdminMessages.For(outcome.Result);
            }

            return outcome;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Admin action {Action} on user {UserId} failed.", actionName, Id);
            ErrorMessage = AdminMessages.Unexpected;
            return null;
        }
    }

    private async Task<bool> LoadAsync(CancellationToken cancellationToken)
    {
        Target = await userStore.FindByIdAsync(Id, cancellationToken);
        if (Target is null)
        {
            return false;
        }

        Catalog = await roleStore.GetAllAsync(cancellationToken);
        RolesMissingFromCatalog = Target.Roles
            .Where(r => !Catalog.Any(c => string.Equals(c.Name, r, StringComparison.OrdinalIgnoreCase)))
            .ToList();
        IsSelf = Target.Id == AdminActor.From(User).Id;
        return true;
    }
}
