using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Qertum.Audit;
using Qertum.Services;
using Qertum.Services.Issuers;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Issuers;

public sealed class IssuerKeyExportTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task PrivateKey_IsPemOfTheIssuersOwnKey_AndAudited()
    {
        var audit = new RecordingAuditLog();
        await using var host = new IssuerApiHost(s => s.Replace(ServiceDescriptor.Singleton<IAuditLogService>(audit)));
        var root = await host.Kit.AddOnlineRootAsync("Export Root", isDefault: true);

        var response = await host.Admin().GetAsync($"/v1/issuers/{root.Id}/private-key", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var pem = await response.Content.ReadAsStringAsync(Ct);
        using var certificate = X509Certificate2.CreateFromPem(root.CertificatePem!, pem);
        Assert.True(certificate.HasPrivateKey);
        Assert.Contains(audit.Entries, e => e.Action == "IssuerKeyDownloaded" && e.Name == "Export Root");
    }

    [Fact]
    public async Task Pfx_RoundTripsWithThePassword_AndIsAudited()
    {
        var audit = new RecordingAuditLog();
        await using var host = new IssuerApiHost(s => s.Replace(ServiceDescriptor.Singleton<IAuditLogService>(audit)));
        var root = await host.Kit.AddOnlineRootAsync("Pfx Root", isDefault: true);

        var response = await host.Admin().PostAsJsonAsync($"/v1/issuers/{root.Id}/pfx", new ExportIssuerPfxRequest("s3cret"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var loaded = X509CertificateLoader.LoadPkcs12(await response.Content.ReadAsByteArrayAsync(Ct), "s3cret");
        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(X509Certificate2.CreateFromPem(root.CertificatePem!).Thumbprint, loaded.Thumbprint);
        Assert.Contains(audit.Entries, e => e.Action == "IssuerPfxExported");
    }

    [Fact]
    public async Task Exports_AreWrittenToTheRealChainedAuditFile_WithoutKeyMaterial()
    {
        var dir = Directory.CreateTempSubdirectory("issuer-audit-").FullName;
        try
        {
            var pattern = Path.Combine(dir, "audit-.clef");
            await using (var host = new IssuerApiHost(s => s.PostConfigure<AuditLogOptions>(o => o.File.Path = pattern)))
            {
                var root = await host.Kit.AddOnlineRootAsync("Audited Root", isDefault: true);
                var admin = host.Admin();
                Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync($"/v1/issuers/{root.Id}/private-key", Ct)).StatusCode);
                Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync($"/v1/issuers/{root.Id}/pfx", new ExportIssuerPfxRequest("pw"), Ct)).StatusCode);
                Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/v1/issuers/{Guid.NewGuid()}/private-key", Ct)).StatusCode);
            }

            var files = Directory.GetFiles(dir, "audit-*.clef");
            var text = string.Concat(files.Select(File.ReadAllText));
            Assert.Contains("IssuerKeyDownloaded", text);
            Assert.Contains("IssuerPfxExported", text);
            Assert.Contains("Audited Root", text);
            Assert.DoesNotContain("PRIVATE KEY", text);
            Assert.Equal(2, text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Count(l => l.Contains("\"Issuer") && l.Contains("ChainHash")));

            var report = AuditChainVerifier.Verify(files);
            Assert.True(report.Ok);
            Assert.True(Assert.Single(report.Chains).Entries >= 2);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* best effort */ }
        }
    }

    [Theory]
    [InlineData("private-key", "IssuerKeyDownloaded")]
    [InlineData("pfx", "IssuerPfxExported")]
    public async Task Export_EnqueuesAKeyAccessWebhook_NamingTheKeyButNotTheIssuer(string route, string expectedEvent)
    {
        await using var host = new IssuerApiHost();
        var root = await host.Kit.AddOnlineRootAsync("Hooked Root", isDefault: true);
        await using (var db = host.Kit.Database.CreateContext())
        {
            db.Webhooks.Add(new Webhook
            {
                Id = new WebhookId(Guid.NewGuid()), Name = "key-egress", Url = "https://h.invalid/k?t={publicKeyThumbprint}",
                Family = WebhookEventFamily.KeyAccess, EventsJson = "[]", IsEnabled = true,
                CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(Ct);
        }

        var response = route == "pfx"
            ? await host.Admin().PostAsJsonAsync($"/v1/issuers/{root.Id}/pfx", new ExportIssuerPfxRequest("pw"), Ct)
            : await host.Admin().GetAsync($"/v1/issuers/{root.Id}/private-key", Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        await using var read = host.Kit.Database.CreateContext();
        var delivery = Assert.Single(await read.WebhookDeliveries.AsNoTracking().ToListAsync(Ct));
        var thumbprint = PublicKeyThumbprint.FromCertificatePem(root.CertificatePem)!;
        Assert.Equal(expectedEvent, delivery.EventType);
        Assert.Null(delivery.ResourceId);
        Assert.Null(delivery.ResourceName);
        Assert.DoesNotContain("Hooked Root", delivery.Payload);
        Assert.Contains(thumbprint, delivery.Payload);
        Assert.Equal($"https://h.invalid/k?t={thumbprint}", delivery.ResolvedUrl);
    }

    [Fact]
    public async Task Refusals_EnqueueNoWebhook()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await using (var db = host.Kit.Database.CreateContext())
        {
            db.Webhooks.Add(new Webhook
            {
                Id = new WebhookId(Guid.NewGuid()), Name = "key-egress", Url = "https://h.invalid/k",
                Family = WebhookEventFamily.KeyAccess, EventsJson = "[]", IsEnabled = true,
                CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(Ct);
        }

        await host.Admin().GetAsync($"/v1/issuers/{Guid.NewGuid()}/private-key", Ct);

        await using var read = host.Kit.Database.CreateContext();
        Assert.Empty(await read.WebhookDeliveries.ToListAsync(Ct));
    }

    [Theory]
    [InlineData("GET", "private-key")]
    [InlineData("POST", "pfx")]
    public async Task NonAdmin_Is403_AndNothingIsAudited(string method, string route)
    {
        var audit = new RecordingAuditLog();
        await using var host = new IssuerApiHost(s => s.Replace(ServiceDescriptor.Singleton<IAuditLogService>(audit)));
        var root = await host.Kit.AddOnlineRootAsync("Guarded Root", isDefault: true);
        await host.GrantAsync("manager", AppPermissions.CertificatesManage, AppPermissions.CertificatesView);

        var request = new HttpRequestMessage(new HttpMethod(method), $"/v1/issuers/{root.Id}/{route}");
        if (method == "POST") request.Content = JsonContent.Create(new ExportIssuerPfxRequest("x"));
        var response = await host.Role("manager").SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Empty(audit.Entries);
    }

    [Theory]
    [InlineData(IssuerStatus.Archived)]
    [InlineData(IssuerStatus.PendingCertificate)]
    public async Task IssuerWithoutALiveKey_Is404(IssuerStatus status)
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var issuer = await host.Kit.AddOnlineRootAsync("Gone Root", status: status);
        await host.Registry.InvalidateAsync(Ct);

        Assert.Equal(HttpStatusCode.NotFound, (await host.Admin().GetAsync($"/v1/issuers/{issuer.Id}/private-key", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.Admin().PostAsJsonAsync($"/v1/issuers/{issuer.Id}/pfx", new ExportIssuerPfxRequest("x"), Ct)).StatusCode);
    }

    [Fact]
    public async Task UnknownIssuer_Is404()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();

        Assert.Equal(HttpStatusCode.NotFound, (await host.Admin().GetAsync($"/v1/issuers/{Guid.NewGuid()}/private-key", Ct)).StatusCode);
    }

    private sealed class RecordingAuditLog : IAuditLogService
    {
        public List<(string Action, string? Name)> Entries { get; } = [];

        public Task LogAsync(string action, string performedBy, Guid? resourceId = null, string? resourceName = null,
            string? detail = null, CancellationToken cancellationToken = default)
        {
            Entries.Add((action, resourceName));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }
}
