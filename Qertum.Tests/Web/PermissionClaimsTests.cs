using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

public sealed class PermissionClaimsTests
{
    private static IAuthorizationService BuildAuthorization()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddQertumWebAuthorization();
        return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
    }

    private static ClaimsPrincipal User(params string[] permissions) =>
        new(new ClaimsIdentity(
            permissions.Select(p => new Claim(QertumWebClaims.Permission, p)).Append(new Claim("sub", "u1")),
            "TestAuth"));

    [Fact]
    public async Task PolicyPerPermission_MatchesTheClaim()
    {
        var authorization = BuildAuthorization();
        var editor = User(AppPermissions.SettingsEdit);

        Assert.True((await authorization.AuthorizeAsync(editor, null, AppPermissions.SettingsEdit)).Succeeded);
        Assert.False((await authorization.AuthorizeAsync(editor, null, AppPermissions.CertificatesManage)).Succeeded);
    }

    [Fact]
    public async Task EveryPermissionHasAPolicy()
    {
        var authorization = BuildAuthorization();
        var all = User([.. AppPermissions.All]);

        foreach (var permission in AppPermissions.All)
            Assert.True((await authorization.AuthorizeAsync(all, null, permission)).Succeeded);
    }
}
