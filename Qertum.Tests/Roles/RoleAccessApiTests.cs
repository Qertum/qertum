using System.Net.Http.Json;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RoleAccessApiTests
{
    [Fact]
    public async Task Overview_AdminOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "editors", [AppPermissions.SettingsEdit], ct);

        using var editor = RolePermissionsApiTests.AsRole(factory, "editors");
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.GetAsync("/v1/permissions/overview", ct)).StatusCode);

        using var admin = RolePermissionsApiTests.Admin(factory);
        var overview = await admin.GetFromJsonAsync<RolePermissionsOverviewResponse>("/v1/permissions/overview", ct);
        var editors = Assert.Single(overview!.Roles);
        Assert.Equal("editors", editors.Name);
        // The editor's own 403 request above was observed by the middleware.
        Assert.False(editors.NeverSeen);
    }

    [Fact]
    public async Task MyAccess_ReturnsCallersRolesAndGrants()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "viewers", [AppPermissions.CertificatesView], ct);
        using var viewer = RolePermissionsApiTests.AsRole(factory, "Viewers");

        var access = await viewer.GetFromJsonAsync<MyAccessResponse>("/v1/me/access", ct);

        Assert.Equal(["Viewers"], access!.Roles);
        Assert.False(access.IsAdmin);
        Assert.Equal([AppPermissions.CertificatesView], access.Permissions.Where(p => p.Granted).Select(p => p.Name));
    }

    [Fact]
    public async Task MyAccess_Anonymous_Returns401()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/v1/me/access", ct)).StatusCode);
    }
}
