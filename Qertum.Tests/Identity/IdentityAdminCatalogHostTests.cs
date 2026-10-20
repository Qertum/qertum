using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;
using static Qertum.Tests.Identity.IdentityHostTestKit;

namespace Qertum.Tests.Identity;

public sealed class IdentityAdminCatalogHostTests : IDisposable
{
    private const string Password = "Admin-Catalog-Test-1!";
    private readonly List<string> _dataPaths = [];

    public void Dispose()
    {
        foreach (var dir in _dataPaths)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    private WebApplicationFactory<IdentityServiceProgram> Factory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-admin-catalog-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _dataPaths.Add(dir);
        return CreateFactory(dir);
    }

    private static async Task<HttpClient> SignedInAdminAsync(WebApplicationFactory<IdentityServiceProgram> factory, CancellationToken ct)
    {
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("boss", "boss@t.local", "Boss", Password, ["admin"], false, ct);
        var client = CreateClient(factory);
        await LoginAsync(client, "boss", Password, ct);
        await ConfirmStepUpAsync(client, Password, ct);
        return client;
    }

    [Theory]
    [InlineData("/Admin/Roles")]
    [InlineData("/Admin/Audit")]
    public async Task NonAdmin_IsForbidden(string url)
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("viewer1", "v@t.local", "V", Password, ["viewer"], false, ct);
        using var client = CreateClient(factory);
        await LoginAsync(client, "viewer1", Password, ct);

        using var response = await client.GetAsync(url, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task RolesPage_CreatesUpdatesAndDeletes_AndTheAuditPageListsThemNewestFirst()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);

        using (var create = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Create",
                   [KeyValuePair.Create("Name", "auditor"), KeyValuePair.Create("Description", "Reads logs.")], ct))
        {
            Assert.Equal(HttpStatusCode.OK, create.StatusCode);
            Assert.Contains("Reads logs.", await create.Content.ReadAsStringAsync(ct));
        }

        using (var update = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Update",
                   [KeyValuePair.Create("Name", "auditor"), KeyValuePair.Create("Description", "Reads audit logs.")], ct))
        {
            Assert.Contains("Reads audit logs.", await update.Content.ReadAsStringAsync(ct));
        }

        using (var delete = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Delete",
                   [KeyValuePair.Create("Name", "auditor")], ct))
        {
            Assert.Equal(HttpStatusCode.OK, delete.StatusCode);
        }

        Assert.DoesNotContain(await factory.Services.GetRequiredService<JsonRoleStore>().GetAllAsync(ct), r => r.Name == "auditor");

        using var audit = await admin.GetAsync("/Admin/Audit", ct);
        var page = await audit.Content.ReadAsStringAsync(ct);
        Assert.Equal(HttpStatusCode.OK, audit.StatusCode);
        // Only the table body: the filter form's action dropdown lists every action name too.
        var html = page[page.IndexOf("<tbody>", StringComparison.Ordinal)..];
        var deleted = html.IndexOf(IdentityAuditActions.RoleDeleted, StringComparison.Ordinal);
        var updated = html.IndexOf(IdentityAuditActions.RoleUpdated, StringComparison.Ordinal);
        var created = html.IndexOf(IdentityAuditActions.RoleCreated, StringComparison.Ordinal);
        Assert.True(deleted >= 0 && deleted < updated && updated < created, "Audit entries are not listed newest first.");
    }

    [Fact]
    public async Task RolesPage_RenamesARoleAndWarnsAboutTheCa()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);

        using (var create = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Create",
                   [KeyValuePair.Create("Name", "ops"), KeyValuePair.Create("Description", "Operators.")], ct))
        {
            Assert.Equal(HttpStatusCode.OK, create.StatusCode);
        }

        using var rename = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Rename",
            [KeyValuePair.Create("Name", "ops"), KeyValuePair.Create("NewName", "platform")], ct);

        Assert.Equal(HttpStatusCode.OK, rename.StatusCode);
        var html = await rename.Content.ReadAsStringAsync(ct);
        Assert.Contains("platform", html);
        // The CA holds the grants and is never called from here.
        Assert.Contains("CA", html, StringComparison.Ordinal);

        var catalog = await factory.Services.GetRequiredService<JsonRoleStore>().GetAllAsync(ct);
        Assert.Contains(catalog, r => r.Name == "platform");
        Assert.DoesNotContain(catalog, r => r.Name == "ops");
    }

    [Fact]
    public async Task RolesPage_DeletingAHeldRole_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        await factory.Services.GetRequiredService<JsonRoleStore>().CreateAsync("viewer", "", ct);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("holder", "h@t.local", "H", Password, ["viewer"], false, ct);

        using var response = await PostFormAsync(admin, "/Admin/Roles", "/Admin/Roles?handler=Delete",
            [KeyValuePair.Create("Name", "viewer")], ct);

        Assert.Contains("This role is still assigned to at least one user.", await response.Content.ReadAsStringAsync(ct));
        Assert.Contains(await factory.Services.GetRequiredService<JsonRoleStore>().GetAllAsync(ct), r => r.Name == "viewer");
    }

    [Fact]
    public async Task AuditPage_PagesFiftyAtATime()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var log = factory.Services.GetRequiredService<IIdentityAuditLog>();
        for (var i = 0; i < 51; i++)
        {
            log.Write(IdentityAuditActions.RoleUpdated, "boss", resourceName: $"bulk-{i:D2}");
        }

        using (var first = await admin.GetAsync("/Admin/Audit", ct))
        {
            var html = await first.Content.ReadAsStringAsync(ct);
            Assert.Contains("bulk-50", html);
            Assert.DoesNotContain("bulk-00", html);
            Assert.Contains("href=\"/Admin/Audit?p=2\"", html);
        }

        using var second = await admin.GetAsync("/Admin/Audit?p=2", ct);
        var secondHtml = await second.Content.ReadAsStringAsync(ct);
        Assert.Contains("bulk-00", secondHtml);
        Assert.Contains("href=\"/Admin/Audit?p=1\"", secondHtml);
    }

    [Fact]
    public async Task ProfilePage_ShowsOwnRolesWithDescriptions()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        await factory.Services.GetRequiredService<JsonRoleStore>().CreateAsync("viewer", "Can view certificates.", ct);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("reader", "r@t.local", "R", Password, ["viewer", "unlisted"], false, ct);
        using var client = CreateClient(factory);
        await LoginAsync(client, "reader", Password, ct);

        using var response = await client.GetAsync("/Account", ct);
        var html = await response.Content.ReadAsStringAsync(ct);

        Assert.Contains("Can view certificates.", html);
        Assert.Contains("No description", html);
    }
}
