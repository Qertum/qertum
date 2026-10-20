using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CertificateRequestPreviewApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
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

    [Fact]
    public async Task Preview_AnswersOkAndAllowedForAnOrdinaryRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "preview-ok.example.com",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(ct))!;
        Assert.True(body.Allowed);
        Assert.Equal("WebServer", body.TemplateTypeKey);
        Assert.Equal("RSA", body.EffectiveKeyAlgorithm);
    }

    [Fact]
    public async Task Preview_AnswersOkWithViolationsForARejection()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        }

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "nope.other.net",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(ct))!;
        Assert.False(body.Allowed);
        Assert.Contains(body.Violations, v => v.Rule == PolicyRules.DnsSuffix);
    }

    [Fact]
    public async Task Preview_WritesNoRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        await admin.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "no-row.example.com",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.CertificateRequests.AnyAsync(r => r.CommonName == "no-row.example.com", ct));
    }

    [Fact]
    public async Task Preview_RequiresCertificatesCreate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "preview-viewer", [AppPermissions.CertificatesView], ct);
        using var viewer = AsRole(factory, "preview-viewer");

        var response = await viewer.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "denied.example.com",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Preview_RejectsAMalformedPayloadWith400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests/preview", new
        {
            commonName = "",
            type = "WebServer",
            propertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
