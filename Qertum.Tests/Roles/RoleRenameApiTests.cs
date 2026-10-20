using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RoleRenameApiTests
{
    [Fact]
    public async Task Admin_RenamesGrants()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = RolePermissionsApiTests.Admin(factory);
        await admin.PutAsJsonAsync("/v1/permissions/ops", new { permissions = new[] { AppPermissions.CertificatesView } }, ct);

        var response = await admin.PostAsJsonAsync("/v1/permissions/ops/rename", new { newRole = "platform" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<RoleRenameResponse>(ct);
        Assert.Equal(("platform", "ops"), (body!.Role, body.PreviousRole));

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(["platform"], await db.RolePermissions.Select(r => r.Role).ToListAsync(ct));
    }

    [Fact]
    public async Task MissingSourceIs404_OccupiedTargetIs409_AdminIs400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = RolePermissionsApiTests.Admin(factory);
        await admin.PutAsJsonAsync("/v1/permissions/ops", new { permissions = new[] { AppPermissions.CertificatesView } }, ct);
        await admin.PutAsJsonAsync("/v1/permissions/platform", new { permissions = new[] { AppPermissions.SettingsEdit } }, ct);

        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PostAsJsonAsync("/v1/permissions/nobody/rename", new { newRole = "x" }, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict,
            (await admin.PostAsJsonAsync("/v1/permissions/ops/rename", new { newRole = "platform" }, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PostAsJsonAsync("/v1/permissions/ops/rename", new { newRole = "admin" }, ct)).StatusCode);
    }

    [Fact]
    public async Task SettingsEditHolder_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "editors", [AppPermissions.SettingsEdit], ct);
        using var editor = RolePermissionsApiTests.AsRole(factory, "editors");

        var response = await editor.PostAsJsonAsync("/v1/permissions/editors/rename", new { newRole = "owners" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
