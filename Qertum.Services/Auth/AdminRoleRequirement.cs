using Microsoft.AspNetCore.Authorization;

namespace Qertum.Services.Auth;

/// <summary>
/// Marker requirement for the "admin-role" policy. Satisfied purely from the authenticated
/// principal's claims (via <see cref="IIdentityClaimsMapper"/>) — deliberately independent of
/// any <c>AuthorizationHandlerContext.Resource</c>, so it evaluates correctly for imperative
/// <c>IAuthorizationService.AuthorizeAsync</c> calls, SignalR hubs, Blazor
/// <c>[Authorize]</c>/<c>AuthorizeView</c>, and unit tests — not only HTTP endpoint routing.
/// </summary>
public sealed class AdminRoleRequirement : IAuthorizationRequirement;
