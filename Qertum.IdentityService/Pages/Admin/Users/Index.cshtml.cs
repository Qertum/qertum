using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Pages.Admin.Users;

public sealed class IndexModel(JsonUserStore userStore) : PageModel
{
    [BindProperty(SupportsGet = true)]
    public string? Q { get; set; }

    public IReadOnlyList<StoredUser> Rows { get; private set; } = [];

    public async Task OnGetAsync(CancellationToken cancellationToken)
    {
        var query = Q?.Trim();
        Rows = (await userStore.GetAllAsync(cancellationToken))
            .Where(u => string.IsNullOrEmpty(query)
                        || u.Username.Contains(query, StringComparison.OrdinalIgnoreCase)
                        || u.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
                        || u.Email.Contains(query, StringComparison.OrdinalIgnoreCase))
            .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string StatusOf(StoredUser user) =>
        user.IsDisabled ? "Disabled" : user.MustChangePassword ? "Must change password" : "Active";
}
