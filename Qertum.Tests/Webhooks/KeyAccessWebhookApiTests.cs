using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Webhooks;
using Qertum.Tests.Roles;

namespace Qertum.Tests.Webhooks;

public sealed class KeyAccessWebhookApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    /// <summary>An Issued request holding a real self-signed certificate and its key.</summary>
    private static async Task<(CertificateRequestId Id, string Thumbprint)> SeedIssuedAsync(
        WebApplicationFactory<ApiServiceProgram> factory, string commonName, CancellationToken ct,
        string? requestedBySubject = null, string requestedBy = "Test User")
    {
        using var rsa = RSA.Create(2048);
        var certRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            $"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var certPem = certificate.ExportCertificatePem();
        var keyPem = rsa.ExportPkcs8PrivateKeyPem();

        var id = new CertificateRequestId(Guid.NewGuid());
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.CertificateRequests.Add(new Qertum.Services.CertificateRequest
        {
            Id = id,
            CommonName = commonName,
            Type = "WebServer",
            Status = CertificateRequestStatus.Issued,
            RequestedBy = requestedBy,
            RequestedBySubject = requestedBySubject,
            CertificatePem = certPem,
            PrivateKeyPem = keyPem,
            ValidFrom = DateTime.UtcNow.AddDays(-1),
            ValidTo = DateTime.UtcNow.AddYears(1),
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync(ct);

        return (id, PublicKeyThumbprint.FromCertificatePem(certPem)!);
    }

    private static async Task SeedWebhookAsync(
        WebApplicationFactory<ApiServiceProgram> factory, WebhookEventFamily family, string url, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.Webhooks.Add(new Webhook
        {
            Id = new WebhookId(Guid.NewGuid()),
            Name = $"hook-{family}",
            Url = url,
            Family = family,
            EventsJson = "[]",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        });
        await db.SaveChangesAsync(ct);
    }

    private static async Task<List<WebhookDelivery>> DeliveriesAsync(
        WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        return await db.WebhookDeliveries.AsNoTracking().ToListAsync(ct);
    }

    [Fact]
    public async Task ReusedDisplayNameCannotDownloadLegacyKeyOrPfx()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "viewer", [AppPermissions.CertificatesView], ct);
        using var viewer = RolePermissionsApiTests.AsRole(factory, "viewer");
        viewer.DefaultRequestHeaders.Add("X-Test-Display-Name", "reused name");
        var (id, _) = await SeedIssuedAsync(factory, "legacy-key.example.com", ct,
            requestedBy: "reused name");

        using var key = await viewer.GetAsync($"/v1/certificate-requests/{(Guid)id}/private-key?pqc=false", ct);
        using var pfx = await viewer.PostAsJsonAsync($"/v1/certificate-requests/{(Guid)id}/pfx",
            new ExportPfxRequest("password", Pqc: false, IncludeChain: false), ct);

        Assert.Equal(HttpStatusCode.Forbidden, key.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, pfx.StatusCode);
    }

    [Fact]
    public async Task MappedOwnerCanDownloadKeyAndPfx()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "viewer", [AppPermissions.CertificatesView], ct);
        using var viewer = RolePermissionsApiTests.AsRole(factory, "viewer");
        var (id, _) = await SeedIssuedAsync(factory, "mapped-key.example.com", ct,
            requestedBySubject: "sub-viewer", requestedBy: "old display name");

        using var key = await viewer.GetAsync($"/v1/certificate-requests/{(Guid)id}/private-key?pqc=false", ct);
        using var pfx = await viewer.PostAsJsonAsync($"/v1/certificate-requests/{(Guid)id}/pfx",
            new ExportPfxRequest("password", Pqc: false, IncludeChain: false), ct);

        Assert.Equal(HttpStatusCode.OK, key.StatusCode);
        Assert.Equal(HttpStatusCode.OK, pfx.StatusCode);
    }

    [Fact]
    public async Task PrivateKeyDownload_EnqueuesKeyAccessWithoutTheCommonName()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        await SeedWebhookAsync(factory, WebhookEventFamily.KeyAccess, "https://h.invalid/k?t={publicKeyThumbprint}", ct);
        var (id, thumbprint) = await SeedIssuedAsync(factory, "keyaccess-download.example.com", ct);

        var response = await admin.GetAsync($"/v1/certificate-requests/{(Guid)id}/private-key?pqc=false", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var delivery = Assert.Single(await DeliveriesAsync(factory, ct));
        Assert.Equal(WellKnownWebhookEvents.PrivateKeyDownloaded, delivery.EventType);
        Assert.Null(delivery.ResourceId);
        Assert.Null(delivery.ResourceName);
        Assert.DoesNotContain("keyaccess-download.example.com", delivery.Payload);
        Assert.Contains(thumbprint, delivery.Payload);
        Assert.Equal($"https://h.invalid/k?t={thumbprint}", delivery.ResolvedUrl);
    }

    [Fact]
    public async Task PfxExport_EnqueuesPfxExported()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        await SeedWebhookAsync(factory, WebhookEventFamily.KeyAccess, "https://h.invalid/k?t={publicKeyThumbprint}", ct);
        var (id, thumbprint) = await SeedIssuedAsync(factory, "keyaccess-pfx.example.com", ct);

        var response = await admin.PostAsJsonAsync(
            $"/v1/certificate-requests/{(Guid)id}/pfx",
            new ExportPfxRequest("pfx-test-password", Pqc: false, IncludeChain: false),
            ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var delivery = Assert.Single(await DeliveriesAsync(factory, ct));
        Assert.Equal(WellKnownWebhookEvents.PfxExported, delivery.EventType);
        Assert.Null(delivery.ResourceName);
        Assert.Equal($"https://h.invalid/k?t={thumbprint}", delivery.ResolvedUrl);
    }

    [Fact]
    public async Task ACertificateRequestWebhookDoesNotReceiveKeyAccessEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        await SeedWebhookAsync(factory, WebhookEventFamily.CertificateRequest, "https://h.invalid/c", ct);
        var (id, _) = await SeedIssuedAsync(factory, "keyaccess-wrongfamily.example.com", ct);

        var response = await admin.GetAsync($"/v1/certificate-requests/{(Guid)id}/private-key?pqc=false", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        Assert.Empty(await DeliveriesAsync(factory, ct));
    }
}
