using System.Net.Http.Json;
using System.Text.Json;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Roles;

/// <summary>
/// Parses real API responses through the DTOs <c>qca permissions</c> uses, so a server-side rename
/// fails here instead of blanking a CLI column.
/// </summary>
public sealed class PermissionCommandsTests
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task CliDtos_ParseRealResponses()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = RolePermissionsApiTests.Admin(factory);
        using var viewer = RolePermissionsApiTests.AsRole(factory, "viewers");

        var put = await admin.PutAsJsonAsync("/v1/permissions/viewers",
            new { permissions = new[] { AppPermissions.CertificatesView } }, ct);
        var change = JsonSerializer.Deserialize<RolePermissionChange>(await put.Content.ReadAsStringAsync(ct), JsonWeb)!;
        Assert.Equal("viewers", change.Role);
        Assert.Equal([AppPermissions.CertificatesView], change.Granted);
        Assert.Empty(change.Revoked);
        Assert.False(change.IsNoOp);

        await viewer.GetAsync("/v1/me/access", ct);

        var overviewBody = await admin.GetStringAsync("/v1/permissions/overview", ct);
        var overview = JsonSerializer.Deserialize<RolePermissionsOverviewResponse>(overviewBody, JsonWeb)!;
        Assert.Equal(AppPermissions.All, overview.Permissions.Select(p => p.Name));
        Assert.All(overview.Permissions, p => Assert.False(string.IsNullOrWhiteSpace(p.Description)));
        var role = Assert.Single(overview.Roles);
        Assert.Equal("viewers", role.Name);
        Assert.Equal([AppPermissions.CertificatesView], role.Permissions);
        Assert.False(role.NeverSeen);
        Assert.NotNull(role.LastSeenUtc);
        Assert.Equal(30, overview.StaleAfterDays);

        var meBody = await viewer.GetStringAsync("/v1/me/access", ct);
        var me = JsonSerializer.Deserialize<MyAccessResponse>(meBody, JsonWeb)!;
        Assert.Equal(["viewers"], me.Roles);
        Assert.False(me.IsAdmin);
        Assert.Equal([AppPermissions.CertificatesView], me.Permissions.Where(p => p.Granted).Select(p => p.Name));
    }

    [Theory]
    [InlineData(null, false, "Pass --permission at least once, or --clear.")]
    [InlineData(new[] { "certificates.view" }, true, "Pass either --permission or --clear, not both.")]
    public void Set_RequiresExactlyOneOfPermissionOrClear(string[]? permissions, bool clear, string expected)
        => Assert.Equal(expected, PermissionCommands.ValidateSetArguments(permissions, clear));

    [Fact]
    public void Set_AcceptsPermissionsOrClear()
    {
        Assert.Null(PermissionCommands.ValidateSetArguments(["certificates.view"], clear: false));
        Assert.Null(PermissionCommands.ValidateSetArguments(null, clear: true));
    }
}
