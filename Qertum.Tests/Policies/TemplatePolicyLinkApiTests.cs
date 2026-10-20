using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class TemplatePolicyLinkApiTests
{
    private const string WebServerTemplateId = "00000000-0000-0000-0000-000000000001";
    private const string SubordinateCaTemplateId = "00000000-0000-0000-0000-000000000005";

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    /// <summary>Seeds a published policy linked to another template, so it can be linked elsewhere through the API.</summary>
    private static async Task<IssuancePolicyId> SeedPolicyAsync(WebApplicationFactory<ApiServiceProgram> factory,
        CancellationToken ct, string[]? dnsSuffixes = null, int? maxValidityDays = null, string linkedTo = "CodeSigning")
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var version = await PolicySeeding.LinkPublishedPolicyAsync(db, linkedTo,
            dnsSuffixes: dnsSuffixes, maxValidityDays: maxValidityDays, ct: ct);
        return version.PolicyId;
    }

    private static Task<HttpResponseMessage> LinkAsync(HttpClient client, string templateId, IssuancePolicyId? policyId, CancellationToken ct) =>
        client.PutAsJsonAsync($"/v1/certificate-templates/{templateId}/issuance-policy",
            new { issuancePolicyId = policyId?.Value }, ct);

    [Fact]
    public async Task Link_AsAdmin_TakesEffectOnTheNextRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var policyId = await SeedPolicyAsync(factory, ct, dnsSuffixes: ["corp.example.com"]);
        using var admin = Admin(factory);

        var link = await LinkAsync(admin, WebServerTemplateId, policyId, ct);
        var request = await admin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = "host.other.net", Type = "WebServer", PropertiesJson = "{}" }, ct);

        Assert.Equal(HttpStatusCode.OK, link.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, request.StatusCode);
    }

    [Fact]
    public async Task Link_WithSettingsEditOnly_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var policyId = await SeedPolicyAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "drafters", Permission = AppPermissions.SettingsEdit });
            await db.SaveChangesAsync(ct);
        }
        using var drafter = factory.CreateClient();
        drafter.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "drafters");

        var link = await LinkAsync(drafter, WebServerTemplateId, policyId, ct);

        Assert.Equal(HttpStatusCode.Forbidden, link.StatusCode);
    }

    [Fact]
    public async Task Link_ToPolicyWithoutPublishedVersion_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await admin.PostAsJsonAsync("/v1/issuance-policies", new { name = "draft-only" }, ct);
        var policy = (await created.Content.ReadFromJsonAsync<IssuancePolicyResponse>(ct))!;

        var link = await LinkAsync(admin, WebServerTemplateId, policy.Id, ct);

        Assert.Equal(HttpStatusCode.BadRequest, link.StatusCode);
    }

    [Fact]
    public async Task Link_WhenTemplateDefaultValidityExceedsPolicyMax_Returns422()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var policyId = await SeedPolicyAsync(factory, ct, maxValidityDays: 825);
        using var admin = Admin(factory);

        var link = await LinkAsync(admin, SubordinateCaTemplateId, policyId, ct); // seeded 3650 days

        Assert.Equal(HttpStatusCode.UnprocessableEntity, link.StatusCode);
    }

    [Fact]
    public async Task Unlink_RestoresUnrestrictedIssuance()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedPolicyAsync(factory, ct, dnsSuffixes: ["corp.example.com"], linkedTo: "WebServer");
        using var admin = Admin(factory);

        var unlink = await LinkAsync(admin, WebServerTemplateId, null, ct);
        var request = await admin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = "host.other.net", Type = "WebServer", PropertiesJson = "{}" }, ct);

        Assert.Equal(HttpStatusCode.OK, unlink.StatusCode);
        Assert.Equal(HttpStatusCode.Created, request.StatusCode);
    }

    [Fact]
    public async Task TemplateSave_KeepsTheLink_AndEnforcesTheValidityInvariant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var policyId = await SeedPolicyAsync(factory, ct, maxValidityDays: 400, linkedTo: "WebServer");
        using var admin = Admin(factory);

        static object Body(int validityDays) => new
        {
            Name = "Web Server (TLS)",
            TypeKey = "WebServer",
            KeyUsagesJson = """["DigitalSignature","KeyEncipherment"]""",
            ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.1"]""",
            SanTypesJson = """["dns","ip"]""",
            ValidityDays = validityDays
        };

        var tooLong = await admin.PutAsJsonAsync($"/v1/certificate-templates/{WebServerTemplateId}", Body(500), ct);
        var fine = await admin.PutAsJsonAsync($"/v1/certificate-templates/{WebServerTemplateId}", Body(200), ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, tooLong.StatusCode);
        Assert.Equal(HttpStatusCode.OK, fine.StatusCode);
        using var scope = factory.Services.CreateScope();
        var template = await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateTemplates.AsNoTracking().SingleAsync(t => t.TypeKey == "WebServer", ct);
        Assert.Equal(policyId, template.IssuancePolicyId);
        Assert.Equal(200, template.ValidityDays);
    }
}
