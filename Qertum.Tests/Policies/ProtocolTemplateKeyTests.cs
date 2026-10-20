using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>
/// <c>CaSettings.AcmeTemplateTypeKey</c> / <c>EstTemplateTypeKey</c> choose the template — and so the
/// issuance policy — for each protocol. Changing one changes what is enforced, so it needs
/// <c>policies.publish</c>, and the key must name a template that exists.
/// </summary>
public sealed class ProtocolTemplateKeyTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task SeedRoleAsync(WebApplicationFactory<ApiServiceProgram> factory, string role,
        string[] permissions, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(permissions.Select(p => new RolePermission { Role = role, Permission = p }));
        await db.SaveChangesAsync(ct);
    }

    private static async Task<CaSettings> CurrentSettingsAsync(HttpClient client, CancellationToken ct) =>
        (await client.GetFromJsonAsync<CaSettings>("/v1/settings", ct))!;

    [Fact]
    public async Task Settings_DefaultBothKeysToWebServer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var settings = await CurrentSettingsAsync(admin, ct);

        Assert.Equal("WebServer", settings.AcmeTemplateTypeKey);
        Assert.Equal("WebServer", settings.EstTemplateTypeKey);
    }

    [Fact]
    public async Task Settings_UnknownTemplateKey_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var settings = await CurrentSettingsAsync(admin, ct);
        settings.AcmeTemplateTypeKey = "NoSuchTemplate";

        var response = await admin.PutAsJsonAsync("/v1/settings", settings, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Settings_ChangingAKey_NeedsPoliciesPublish()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "editors", [AppPermissions.SettingsEdit], ct);
        using var admin = Admin(factory);
        using var editor = factory.CreateClient();
        editor.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "editors");

        var settings = await CurrentSettingsAsync(admin, ct);
        settings.EstTemplateTypeKey = "ClientAuth";
        var changed = await editor.PutAsJsonAsync("/v1/settings", settings, ct);

        var unchanged = await CurrentSettingsAsync(admin, ct);
        unchanged.ExpiringSoonDays = 45;
        var untouched = await editor.PutAsJsonAsync("/v1/settings", unchanged, ct);

        Assert.Equal(HttpStatusCode.Forbidden, changed.StatusCode);
        Assert.Equal(HttpStatusCode.OK, untouched.StatusCode);
    }

    [Fact]
    public async Task Settings_ValidityAboveALinkedPolicyMaximum_Returns422()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            // ClientAuth has no ValidityDays of its own, so it falls back to the global default.
            var template = await db.CertificateTemplates.SingleAsync(t => t.TypeKey == "ClientAuth", ct);
            template.ValidityDays = null;
            await db.SaveChangesAsync(ct);
            await PolicySeeding.LinkPublishedPolicyAsync(db, "ClientAuth", maxValidityDays: 90, ct: ct);
        }
        using var admin = Admin(factory);
        var settings = await CurrentSettingsAsync(admin, ct);
        settings.CertificateValidityDays = 400;

        var response = await admin.PutAsJsonAsync("/v1/settings", settings, ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
    }

    [Fact]
    public async Task DeletingATemplateNamedByAProtocolKey_Returns409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        Guid templateId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var template = new CertificateTemplate
            {
                Name = "Protocol target",
                TypeKey = "ProtocolTarget",
                KeyUsagesJson = """["DigitalSignature"]""",
                ExtendedKeyUsagesJson = "[]",
                SanTypesJson = """["dns"]"""
            };
            db.CertificateTemplates.Add(template);
            var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1, ct);
            if (settings is null)
            {
                settings = new CaSettings { PqcStage = PqcStage.Off };
                db.Settings.Add(settings);
            }
            settings.AcmeTemplateTypeKey = "ProtocolTarget";
            await db.SaveChangesAsync(ct);
            templateId = template.Id;
        }

        var response = await admin.DeleteAsync($"/v1/certificate-templates/{templateId}", ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }
}
