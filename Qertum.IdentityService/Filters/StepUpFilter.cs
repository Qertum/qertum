using Qertum.IdentityService.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Qertum.IdentityService.Filters;

/// <summary>
/// Sends an admin whose step-up is missing or older than <see cref="StepUp.Window"/> to
/// <see cref="StepUp.ConfirmPath"/>. Applied to the whole /Admin folder (see Program.cs), so a page
/// added there later is covered. Runs after authorization, so a non-admin gets 403 and never sees the
/// prompt, and after <see cref="ForcedPasswordChangeFilter"/>.
/// </summary>
public sealed class StepUpFilter(TimeProvider timeProvider) : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        if (string.Equals(context.ActionDescriptor.ViewEnginePath, StepUp.ConfirmPath, StringComparison.OrdinalIgnoreCase))
        {
            await next();
            return;
        }

        var http = context.HttpContext;
        var auth = await http.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (auth.Succeeded && StepUp.IsFresh(auth.Properties, timeProvider.GetUtcNow()))
        {
            await next();
            return;
        }

        var request = http.Request;
        var isRead = HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method);

        // A read comes back to the same page. A write cannot be replayed after the redirect, so it
        // returns to the page without its query and the confirm page says to submit again.
        var returnUrl = isRead
            ? request.PathBase + request.Path + request.QueryString
            : (request.PathBase + request.Path).Value ?? "/";
        var target = $"{StepUp.ConfirmPath}?returnUrl={Uri.EscapeDataString(returnUrl)}";
        if (!isRead)
        {
            target += "&expired=true";
        }

        context.Result = new RedirectResult(target);
    }
}
