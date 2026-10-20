using System.Security.Claims;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Qertum.IdentityService.Filters;

/// <summary>
/// Single choke point that stops a cookie session belonging to a flagged account from reaching
/// any Razor Page other than the forced change-password page and sign-out.
/// <para>
/// Registered once for every Razor Page (see <c>Program.cs</c>), so a page added under
/// <c>/Account</c> later is covered without touching it. It deliberately does not apply to MVC
/// controllers: <see cref="Controllers.AuthorizationController"/> owns the <c>/connect/*</c>
/// endpoints and issues its own OpenIddict-shaped responses for the same condition.
/// </para>
/// </summary>
public sealed class ForcedPasswordChangeFilter(JsonUserStore userStore) : IAsyncPageFilter
{
    /// <summary>
    /// Razor Page paths (<c>ViewEnginePath</c>) a flagged user may still reach.
    /// <list type="bullet">
    /// <item><c>/Account/ChangePassword</c> — the destination itself; redirecting it would loop.</item>
    /// <item><c>/Account/Logout</c> — a stuck user must always be able to leave. It is
    /// <c>[AllowAnonymous]</c> and only ever ends a session, so it grants nothing.</item>
    /// </list>
    /// </summary>
    private static readonly string[] ExemptPages =
    [
        "/Account/ChangePassword",
        "/Account/Logout"
    ];

    private const string ForcedChangePasswordUrl = "/Account/ChangePassword?forced=true";

    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(
        PageHandlerExecutingContext context,
        PageHandlerExecutionDelegate next)
    {
        var user = context.HttpContext.User;
        if (user?.Identity?.IsAuthenticated != true)
        {
            // Anonymous requests (/login, /device) are unaffected; there is no account to flag.
            await next();
            return;
        }

        var page = context.ActionDescriptor.ViewEnginePath;
        if (ExemptPages.Contains(page, StringComparer.OrdinalIgnoreCase))
        {
            await next();
            return;
        }

        var subject = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (Guid.TryParse(subject, out var id) &&
            await userStore.RequiresPasswordChangeAsync(id, context.HttpContext.RequestAborted))
        {
            context.Result = new Microsoft.AspNetCore.Mvc.RedirectResult(ForcedChangePasswordUrl);
            return;
        }

        await next();
    }
}
