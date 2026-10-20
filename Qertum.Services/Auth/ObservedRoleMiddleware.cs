using Microsoft.AspNetCore.Http;

namespace Qertum.Services.Auth;

/// <summary>
/// Records the roles on an authenticated request. Runs after authentication and before
/// authorization; awaited so the scoped DbContext is not used after the request ends. The recorder
/// swallows failures, so this never changes a request's outcome.
/// </summary>
public sealed class ObservedRoleMiddleware(RequestDelegate next)
{
    /// <summary>Records the caller's roles, then passes the request on.</summary>
    public async Task InvokeAsync(HttpContext context, IObservedRoleRecorder recorder, IIdentityClaimsMapper claimsMapper)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var roles = claimsMapper.GetRoles(context.User);
            if (roles.Count > 0)
                await recorder.RecordAsync(roles, context.RequestAborted);
        }

        await next(context);
    }
}
