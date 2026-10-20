using Microsoft.AspNetCore.Authorization;

namespace Qertum.Services.Auth;

/// <summary>
/// Satisfies <see cref="AdminRoleRequirement"/> by consulting <see cref="IIdentityClaimsMapper"/>
/// against <c>context.User</c> only. The mapper is registered as a singleton (its only
/// dependency, <see cref="IdentityAuthenticationOptions"/>, is also a singleton), so it can be
/// constructor-injected here without any per-request resource resolution.
/// </summary>
public sealed class AdminRoleAuthorizationHandler : AuthorizationHandler<AdminRoleRequirement>
{
    private readonly IIdentityClaimsMapper _claimsMapper;

    public AdminRoleAuthorizationHandler(IIdentityClaimsMapper claimsMapper)
    {
        _claimsMapper = claimsMapper;
    }

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdminRoleRequirement requirement)
    {
        if (_claimsMapper.IsAdmin(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
