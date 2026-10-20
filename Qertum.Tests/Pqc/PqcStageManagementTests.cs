using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Pqc;

public sealed class PqcStageManagementTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task<HttpClient> SettingsEditorAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "editor", Permission = AppPermissions.SettingsEdit });
            await db.SaveChangesAsync(ct);
        }
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "editor");
        return client;
    }

    [Fact]
    public async Task SettingsSave_CarriesTheStoredStageAcross_EvenWhenAClientPostsAnother()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        (await admin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = "Warn" }, ct)).EnsureSuccessStatusCode();

        var current = (await admin.GetFromJsonAsync<CaSettings>("/v1/settings", ct))!;
        current.PqcStage = PqcStage.Off; // a client trying to weaken the stage through the general save
        current.OrganizationName = "Contoso";
        (await admin.PutAsJsonAsync("/v1/settings", current, ct)).EnsureSuccessStatusCode();

        var after = (await admin.GetFromJsonAsync<CaSettings>("/v1/settings", ct))!;
        Assert.Equal(PqcStage.Warn, after.PqcStage);
        Assert.Equal("Contoso", after.OrganizationName);
    }

    [Fact]
    public async Task ChangingTheStage_NeedsAdmin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var editor = await SettingsEditorAsync(factory, ct);

        var response = await editor.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = "Off" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task MissingStage_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = (string?)null }, ct)).StatusCode);
    }

    [Fact]
    public async Task StageChange_IsAuditedWithBothValues_AndANoOpWritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();

        await service.SetPqcStageAsync(PqcStage.Observe, "admin", ct);
        await service.SetPqcStageAsync(PqcStage.Observe, "admin", ct);

        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "PqcStageChanged");
        Assert.Contains("Off", entry.Detail);
        Assert.Contains("Observe", entry.Detail);
    }

    [Fact]
    public async Task TemplateOverride_CanBeSetAndCleared_AndIsAdminOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        using var editor = await SettingsEditorAsync(factory, ct);
        var templates = (await admin.GetFromJsonAsync<List<CertificateTemplate>>("/v1/certificate-templates", ct))!;
        var web = templates.Single(t => t.TypeKey == "WebServer");

        Assert.Equal(HttpStatusCode.Forbidden,
            (await editor.PutAsJsonAsync($"/v1/certificate-templates/{web.Id}/pqc-stage", new { stage = "Warn" }, ct)).StatusCode);

        var set = await admin.PutAsJsonAsync($"/v1/certificate-templates/{web.Id}/pqc-stage", new { stage = "Warn" }, ct);
        Assert.Equal(PqcStage.Warn, (await set.Content.ReadFromJsonAsync<CertificateTemplate>(ct))!.PqcStageOverride);

        var cleared = await admin.PutAsJsonAsync($"/v1/certificate-templates/{web.Id}/pqc-stage", new { stage = (string?)null }, ct);
        Assert.Null((await cleared.Content.ReadFromJsonAsync<CertificateTemplate>(ct))!.PqcStageOverride);

        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.PutAsJsonAsync($"/v1/certificate-templates/{Guid.NewGuid()}/pqc-stage", new { stage = "Off" }, ct)).StatusCode);
    }

    [Fact]
    public async Task TemplateOverrideChange_IsAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var web = await scope.Db.CertificateTemplates.FirstAsync(t => t.TypeKey == "WebServer", ct);

        await scope.CreateTemplateService().SetPqcStageAsync(web.Id, PqcStage.Pilot, "admin", ct);

        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "TemplatePqcStageChanged");
        Assert.Contains("CA default -> Pilot", entry.Detail);
    }

    [Fact]
    public async Task SaveTemplate_DoesNotTouchTheOverride()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var web = (await admin.GetFromJsonAsync<List<CertificateTemplate>>("/v1/certificate-templates", ct))!.Single(t => t.TypeKey == "WebServer");
        (await admin.PutAsJsonAsync($"/v1/certificate-templates/{web.Id}/pqc-stage", new { stage = "Pilot" }, ct)).EnsureSuccessStatusCode();

        var save = new SaveCertificateTemplateRequest
        {
            Name = web.Name, TypeKey = web.TypeKey, Description = "edited",
            KeyUsagesJson = web.KeyUsagesJson, ExtendedKeyUsagesJson = web.ExtendedKeyUsagesJson, SanTypesJson = web.SanTypesJson
        };
        (await admin.PutAsJsonAsync($"/v1/certificate-templates/{web.Id}", save, ct)).EnsureSuccessStatusCode();

        var after = (await admin.GetFromJsonAsync<CertificateTemplate>($"/v1/certificate-templates/{web.Id}", ct))!;
        Assert.Equal(PqcStage.Pilot, after.PqcStageOverride);
    }

    private static object RsaRoot(string? stage) => new
    {
        commonName = "Test Root", keyAlgorithm = "RSA", validityDays = 365, pqcStage = stage
    };

    private static async Task SetStoredStageAsync(Issuers.IssuerApiHost host, PqcStage stage, CancellationToken ct)
    {
        await using var db = host.Kit.Database.CreateContext();
        (await db.Settings.SingleAsync(ct)).PqcStage = stage;
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Generate_ClassicalRootOnAFreshCa_IsRefusedByTheDefaultStage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = new Issuers.IssuerApiHost();
        await SetStoredStageAsync(host, PqcStage.Enforce, ct);

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/generate", RsaRoot(null), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Generate_WithAStageFromAnAdmin_AppliesItBeforeTheKeyCheck()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = new Issuers.IssuerApiHost();
        await SetStoredStageAsync(host, PqcStage.Enforce, ct);
        var admin = host.Admin();

        var response = await admin.PostAsJsonAsync("/v1/ca/generate", RsaRoot("Off"), ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal(PqcStage.Off, (await admin.GetFromJsonAsync<CaSettings>("/v1/settings", ct))!.PqcStage);
    }

    [Fact]
    public async Task Generate_WithAStageFromANonAdmin_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = new Issuers.IssuerApiHost();
        await SetStoredStageAsync(host, PqcStage.Enforce, ct);
        await host.GrantAsync("editor", AppPermissions.SettingsEdit);

        var response = await host.Role("editor").PostAsJsonAsync("/v1/ca/generate", RsaRoot("Off"), ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
