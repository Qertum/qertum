using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RolePermissionsApiTests
{
    internal static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    internal static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
        return client;
    }

    internal static async Task SeedRoleAsync(WebApplicationFactory<ApiServiceProgram> factory, string role,
        string[] permissions, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(permissions.Select(p => new RolePermission { Role = role, Permission = p }));
        await db.SaveChangesAsync(ct);
    }

    private static async Task<List<RolePermission>> RowsAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        return await db.RolePermissions.AsNoTracking().ToListAsync(ct);
    }

    [Fact]
    public async Task SettingsEditHolder_CannotReadOrChangePermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "editors", [AppPermissions.SettingsEdit], ct);
        using var editor = AsRole(factory, "editors");

        Assert.Equal(HttpStatusCode.Forbidden, (await editor.GetAsync("/v1/permissions", ct)).StatusCode);
        var escalate = await editor.PutAsJsonAsync("/v1/permissions/editors",
            new { permissions = new[] { AppPermissions.SettingsEdit, AppPermissions.PoliciesPublish } }, ct);
        Assert.Equal(HttpStatusCode.Forbidden, escalate.StatusCode);

        var rows = await RowsAsync(factory, ct);
        Assert.DoesNotContain(rows, r => r.Permission == AppPermissions.PoliciesPublish);
    }

    [Fact]
    public async Task Admin_Put_ReturnsChange()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PutAsJsonAsync("/v1/permissions/operators",
            new { permissions = new[] { AppPermissions.CertificatesManage, AppPermissions.CertificatesView } }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var change = (await response.Content.ReadFromJsonAsync<RolePermissionChange>(ct))!;
        Assert.Equal("operators", change.Role);
        Assert.Equal([AppPermissions.CertificatesManage, AppPermissions.CertificatesView], change.Granted);
        Assert.False(change.IsNoOp);

        var again = await admin.PutAsJsonAsync("/v1/permissions/OPERATORS",
            new { permissions = new[] { AppPermissions.CertificatesView, AppPermissions.CertificatesManage } }, ct);
        Assert.True((await again.Content.ReadFromJsonAsync<RolePermissionChange>(ct))!.IsNoOp);
    }

    [Theory]
    [InlineData("%20ops")]
    [InlineData("ops%07")]
    [InlineData("admin")]
    [InlineData("ADMIN")]
    public async Task Put_RefusedRoleName_Returns400(string encodedRole)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PutAsJsonAsync($"/v1/permissions/{encodedRole}",
            new { permissions = new[] { AppPermissions.CertificatesView } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await RowsAsync(factory, ct));
    }

    [Fact]
    public async Task Put_TooLongRoleName_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PutAsJsonAsync($"/v1/permissions/{new string('a', 129)}",
            new { permissions = new[] { AppPermissions.CertificatesView } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Put_UnknownPermission_Returns400ListingItAndSavesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PutAsJsonAsync("/v1/permissions/ops",
            new { permissions = new[] { AppPermissions.CertificatesView, "certs.everything" } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        Assert.Equal("Unknown permissions", body.RootElement.GetProperty("title").GetString());
        Assert.Contains("certs.everything", body.RootElement.GetProperty("detail").GetString());
        Assert.Equal(["certs.everything"],
            body.RootElement.GetProperty("unknownPermissions").EnumerateArray().Select(e => e.GetString()!));
        Assert.Empty(await RowsAsync(factory, ct));
    }

    [Fact]
    public async Task Put_EnqueuesRolePermissionsUpdatedForSettingsWebhook()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.Webhooks.Add(new Webhook
            {
                Name = "settings", Url = "https://hooks.example/settings", Family = WebhookEventFamily.Settings,
                EventsJson = "[]", IsEnabled = true, CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(ct);
        }
        using var admin = Admin(factory);

        await admin.PutAsJsonAsync("/v1/permissions/ops", new { permissions = new[] { AppPermissions.CertificatesView } }, ct);
        await admin.PutAsJsonAsync("/v1/permissions/ops", new { permissions = new[] { AppPermissions.CertificatesView } }, ct);

        using var check = factory.Services.CreateScope();
        var deliveries = await check.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .WebhookDeliveries.AsNoTracking().ToListAsync(ct);
        var delivery = Assert.Single(deliveries);
        Assert.Equal(WellKnownWebhookEvents.RolePermissionsUpdated, delivery.EventType);
        Assert.Contains("\"grantedPermissions\":\"certificates.view\"", delivery.Payload);
    }
}
