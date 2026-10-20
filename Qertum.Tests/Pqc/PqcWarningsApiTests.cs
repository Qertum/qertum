using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcWarningsApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task<(WebApplicationFactory<ApiServiceProgram> Factory, HttpClient Admin)> ArrangeAsync(
        PqcStage stage, CancellationToken ct)
    {
        var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var admin = Admin(factory);
        (await admin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = stage.ToString() }, ct)).EnsureSuccessStatusCode();
        return (factory, admin);
    }

    private static object Rsa(string cn) => new { commonName = cn, type = "WebServer", keyAlgorithm = "RSA" };

    [Fact]
    public async Task Create_AtWarn_ReturnsWarnings_AndOtherReadsDoNot()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Warn, ct);
        await using var _ = factory;
        using var __ = admin;

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests", Rsa("warn.corp.example"), ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        var warning = Assert.Single(created.Warnings!);
        Assert.Contains("classical", warning);

        var read = (await admin.GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{created.Id}", ct))!;
        Assert.Null(read.Warnings);
    }

    [Fact]
    public async Task Create_AtOff_HasNoWarnings()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Off, ct);
        await using var _ = factory;
        using var __ = admin;

        var created = (await (await admin.PostAsJsonAsync("/v1/certificate-requests", Rsa("off.corp.example"), ct))
            .Content.ReadFromJsonAsync<CertificateRequest>(ct))!;

        Assert.Null(created.Warnings);
    }

    [Fact]
    public async Task Create_RequestBodyCannotSetWarnings()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Off, ct);
        await using var _ = factory;
        using var __ = admin;

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests",
            new { commonName = "forged.corp.example", type = "WebServer", keyAlgorithm = "RSA", warnings = new[] { "forged" } }, ct);

        var created = (await response.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        Assert.Null(created.Warnings);
    }

    [Fact]
    public async Task Update_AtWarn_ReturnsWarnings()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Off, ct);
        await using var _ = factory;
        using var __ = admin;
        var created = (await (await admin.PostAsJsonAsync("/v1/certificate-requests", Rsa("upd.corp.example"), ct))
            .Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        (await admin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = "Warn" }, ct)).EnsureSuccessStatusCode();

        var response = await admin.PutAsJsonAsync($"/v1/certificate-requests/{created.Id}",
            new { commonName = "upd.corp.example", type = "WebServer", keyAlgorithm = "RSA", propertiesJson = "{}" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var updated = (await response.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        Assert.Single(updated.Warnings!);
    }

    [Fact]
    public async Task Preview_AtWarn_IsAllowedWithWarnings_AndWritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Warn, ct);
        await using var _ = factory;
        using var __ = admin;

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests/preview", Rsa("preview.corp.example"), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var preview = (await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(ct))!;
        Assert.True(preview.Allowed);
        Assert.Single(preview.Warnings);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.CertificateRequests.AnyAsync(ct));
    }

    [Fact]
    public async Task Preview_AtEnforce_IsHttp200Rejected()
    {
        var ct = TestContext.Current.CancellationToken;
        var (factory, admin) = await ArrangeAsync(PqcStage.Enforce, ct);
        await using var _ = factory;
        using var __ = admin;

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests/preview", Rsa("preview.corp.example"), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var preview = (await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(ct))!;
        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == "pqcOnly");
    }
}
