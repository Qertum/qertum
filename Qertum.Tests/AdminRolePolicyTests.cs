using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services.Auth;

namespace Qertum.Tests;

/// <summary>
/// Pins the behavior that the "admin-role" policy decides purely from the authenticated
/// principal — no dependency on AuthorizationHandlerContext.Resource — so it works for
/// imperative IAuthorizationService.AuthorizeAsync calls with no resource, not only HTTP
/// endpoint routing (see AuthenticationServiceCollectionExtensions.AddQertumAuthorization).
/// </summary>
public sealed class AdminRolePolicyTests
{
    private static IAuthorizationService BuildAuthorizationService()
    {
        var services = new ServiceCollection();
        var options = new IdentityAuthenticationOptions
        {
            Authority = "https://idp.example",
            RoleClaimType = "role"
        };
        services.AddLogging();
        services.AddSingleton(options);
        services.AddSingleton<IIdentityClaimsMapper, IdentityClaimsMapper>();
        services.AddQertumAuthorization();

        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal PrincipalWith(params Claim[] claims) =>
        new(new ClaimsIdentity(claims, authenticationType: "Bearer"));

    [Fact]
    public async Task AdminRolePolicy_WithNoResource_SucceedsForAdmin()
    {
        var authorizationService = BuildAuthorizationService();
        var admin = PrincipalWith(new Claim("role", "admin"));

        var result = await authorizationService.AuthorizeAsync(admin, resource: null, policyName: "admin-role");

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AdminRolePolicy_WithNoResource_FailsForNonAdmin()
    {
        var authorizationService = BuildAuthorizationService();
        var viewer = PrincipalWith(new Claim("role", "viewer"));

        var result = await authorizationService.AuthorizeAsync(viewer, resource: null, policyName: "admin-role");

        Assert.False(result.Succeeded);
    }
}
