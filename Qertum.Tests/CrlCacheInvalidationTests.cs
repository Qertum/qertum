using Qertum.QueueConsumer;
using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>
/// The published CRL is cached for CrlValidityHours. Finalising a revocation has to drop that entry,
/// otherwise relying parties keep fetching a CRL that does not name the certificate just revoked.
/// </summary>
public sealed class CrlCacheInvalidationTests
{
    [Fact]
    public async Task FinalisingARevocation_EvictsThePublishedCrl()
    {
        var ct = TestContext.Current.CancellationToken;

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var services = new ServiceCollection();
        services.AddSingleton<System.Data.Common.DbConnection>(connection);
        services.AddDbContext<CertificateRequestDbContext>((sp, options) =>
            options.UseSqlite(sp.GetRequiredService<System.Data.Common.DbConnection>()));
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        services.AddDistributedMemoryCache();
        services.AddScoped<ICertificateRequestService, CertificateRequestService>();
        services.AddSingleton<Qertum.Services.Policies.IIssuancePolicyEvaluator, Qertum.Services.Policies.IssuancePolicyEvaluator>();
        services.AddScoped<Qertum.Services.Policies.IIssuancePolicyService, Qertum.Services.Policies.IssuancePolicyService>();
        services.AddSingleton<IAuditLogService, NullAuditLogService>();
        services.AddSingleton<IWebhookService, NullWebhookService>();
        services.AddSingleton<ICertificateGenerator, NoopCertificateGenerator>();
        services.AddSingleton<ICertificateTemplateService, NullTemplateService>();
        services.AddLogging();
        services.AddSingleton(new CaDataOptions { Directory = Path.GetTempPath() });
        Qertum.Services.Issuers.IssuerServiceRegistration.AddIssuerRegistry(services);
        services.AddMetrics();
        services.AddQueueConsumerMetrics();
        services.AddSingleton<ICertificateApprovalQueue, CertificateApprovalChannel>();
        services.AddSingleton<ICertificateRevocationQueue, CertificateRevocationChannel>();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["QueueConsumer:IdleDelayMs"] = "50",
                ["QueueConsumer:ProcessingDelayMs"] = "10",
                ["QueueConsumer:ErrorDelayMs"] = "50"
            }).Build());

        await using var provider = services.BuildServiceProvider();

        await using (var seedScope = provider.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await db.Database.EnsureCreatedAsync(ct);
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "revoke-me.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.PendingRevocation,
                CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                SerialNumber = "ABCDEF"
            });
            await db.SaveChangesAsync(ct);
        }

        var cache = provider.GetRequiredService<IDistributedCache>();
        await cache.SetAsync(CrlCache.Key, [1, 2, 3], ct);

        var consumer = new CertificateRequestQueueConsumer(
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<CertificateRequestQueueConsumer>.Instance,
            Microsoft.Extensions.Options.Options.Create(new QueueConsumerOptions { IdleDelayMs = 50, ProcessingDelayMs = 10, ErrorDelayMs = 50 }),
            provider.GetRequiredService<CertificateQueueMetrics>(),
            provider.GetRequiredService<ICertificateApprovalQueue>(),
            provider.GetRequiredService<ICertificateRevocationQueue>());

        await consumer.StartAsync(ct);
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline && await cache.GetAsync(CrlCache.Key, ct) is not null)
                await Task.Delay(50, ct);
        }
        finally
        {
            await consumer.StopAsync(ct);
        }

        Assert.Null(await cache.GetAsync(CrlCache.Key, ct));

        await using var verifyScope = provider.CreateAsyncScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var row = await verifyDb.CertificateRequests.AsNoTracking().SingleAsync(ct);
        Assert.Equal(CertificateRequestStatus.Revoked, row.Status);
    }

    [Fact]
    public async Task FinalisingARevocation_AlsoEvictsThePublishedDeltaCrl()
    {
        var ct = TestContext.Current.CancellationToken;

        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var services = new ServiceCollection();
        services.AddSingleton<System.Data.Common.DbConnection>(connection);
        services.AddDbContext<CertificateRequestDbContext>((sp, options) =>
            options.UseSqlite(sp.GetRequiredService<System.Data.Common.DbConnection>()));
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        services.AddDistributedMemoryCache();
        services.AddScoped<ICertificateRequestService, CertificateRequestService>();
        services.AddSingleton<Qertum.Services.Policies.IIssuancePolicyEvaluator, Qertum.Services.Policies.IssuancePolicyEvaluator>();
        services.AddScoped<Qertum.Services.Policies.IIssuancePolicyService, Qertum.Services.Policies.IssuancePolicyService>();
        services.AddSingleton<IAuditLogService, NullAuditLogService>();
        services.AddSingleton<IWebhookService, NullWebhookService>();
        services.AddSingleton<ICertificateGenerator, NoopCertificateGenerator>();
        services.AddSingleton<ICertificateTemplateService, NullTemplateService>();
        services.AddLogging();
        services.AddSingleton(new CaDataOptions { Directory = Path.GetTempPath() });
        Qertum.Services.Issuers.IssuerServiceRegistration.AddIssuerRegistry(services);
        services.AddMetrics();
        services.AddQueueConsumerMetrics();
        services.AddSingleton<ICertificateApprovalQueue, CertificateApprovalChannel>();
        services.AddSingleton<ICertificateRevocationQueue, CertificateRevocationChannel>();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["QueueConsumer:IdleDelayMs"] = "50",
                ["QueueConsumer:ProcessingDelayMs"] = "10",
                ["QueueConsumer:ErrorDelayMs"] = "50"
            }).Build());

        await using var provider = services.BuildServiceProvider();

        await using (var seedScope = provider.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await db.Database.EnsureCreatedAsync(ct);
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "revoke-me-delta.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.PendingRevocation,
                CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                SerialNumber = "ABCDEF01"
            });
            await db.SaveChangesAsync(ct);
        }

        var cache = provider.GetRequiredService<IDistributedCache>();
        await cache.SetAsync(CrlCache.Key, [1, 2, 3], ct);
        await cache.SetAsync(CrlCache.DeltaKey, [4, 5, 6], ct);

        var consumer = new CertificateRequestQueueConsumer(
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<CertificateRequestQueueConsumer>.Instance,
            Microsoft.Extensions.Options.Options.Create(new QueueConsumerOptions { IdleDelayMs = 50, ProcessingDelayMs = 10, ErrorDelayMs = 50 }),
            provider.GetRequiredService<CertificateQueueMetrics>(),
            provider.GetRequiredService<ICertificateApprovalQueue>(),
            provider.GetRequiredService<ICertificateRevocationQueue>());

        await consumer.StartAsync(ct);
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline && await cache.GetAsync(CrlCache.DeltaKey, ct) is not null)
                await Task.Delay(50, ct);
        }
        finally
        {
            await consumer.StopAsync(ct);
        }

        Assert.Null(await cache.GetAsync(CrlCache.Key, ct));
        Assert.Null(await cache.GetAsync(CrlCache.DeltaKey, ct));
    }

    [Fact]
    public async Task FinalisingARevocation_CountsARevokedOutcome()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var services = new ServiceCollection();
        services.AddSingleton<System.Data.Common.DbConnection>(connection);
        services.AddDbContext<CertificateRequestDbContext>((sp, options) =>
            options.UseSqlite(sp.GetRequiredService<System.Data.Common.DbConnection>()));
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        services.AddDistributedMemoryCache();
        services.AddScoped<ICertificateRequestService, CertificateRequestService>();
        services.AddSingleton<Qertum.Services.Policies.IIssuancePolicyEvaluator, Qertum.Services.Policies.IssuancePolicyEvaluator>();
        services.AddScoped<Qertum.Services.Policies.IIssuancePolicyService, Qertum.Services.Policies.IssuancePolicyService>();
        services.AddSingleton<IAuditLogService, NullAuditLogService>();
        services.AddSingleton<IWebhookService, NullWebhookService>();
        services.AddSingleton<ICertificateGenerator, NoopCertificateGenerator>();
        services.AddSingleton<ICertificateTemplateService, NullTemplateService>();
        services.AddLogging();
        services.AddSingleton(new CaDataOptions { Directory = Path.GetTempPath() });
        Qertum.Services.Issuers.IssuerServiceRegistration.AddIssuerRegistry(services);
        services.AddMetrics();
        services.AddQueueConsumerMetrics();
        services.AddSingleton<ICertificateApprovalQueue, CertificateApprovalChannel>();
        services.AddSingleton<ICertificateRevocationQueue, CertificateRevocationChannel>();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        await using var provider = services.BuildServiceProvider();

        await using (var seedScope = provider.CreateAsyncScope())
        {
            var db = seedScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await db.Database.EnsureCreatedAsync(ct);
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "revoke-me.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.PendingRevocation,
                CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                SerialNumber = "ABCDEF"
            });
            await db.SaveChangesAsync(ct);
        }

        using var recorder = new MetricsRecorder(provider.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>(), OperationsMetrics.MeterName);
        var consumer = new CertificateRequestQueueConsumer(
            provider.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<CertificateRequestQueueConsumer>.Instance,
            Microsoft.Extensions.Options.Options.Create(new QueueConsumerOptions { IdleDelayMs = 50, ProcessingDelayMs = 10, ErrorDelayMs = 50 }),
            provider.GetRequiredService<CertificateQueueMetrics>(),
            provider.GetRequiredService<ICertificateApprovalQueue>(),
            provider.GetRequiredService<ICertificateRevocationQueue>(),
            provider.GetRequiredService<OperationsMetrics>());

        await consumer.StartAsync(ct);
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (DateTime.UtcNow < deadline && recorder.Sum("ca.certificate.revocations") == 0)
                await Task.Delay(50, ct);
        }
        finally
        {
            await consumer.StopAsync(ct);
        }

        Assert.Equal(1, recorder.Sum("ca.certificate.revocations", ("outcome", "revoked")));
    }

    private sealed class NullAuditLogService : IAuditLogService
    {
        public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }

    private sealed class NullWebhookService : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NullTemplateService : ICertificateTemplateService
    {
        public Task<IReadOnlyList<CertificateTemplate>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<CertificateTemplate>>([]);
        public Task<CertificateTemplate?> GetByIdAsync(CertificateTemplateId id, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
        public Task<CertificateTemplate?> GetByTypeKeyAsync(string typeKey, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
        public Task<CertificateTemplate> CreateAsync(CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(template);
        public Task<CertificateTemplate?> UpdateAsync(CertificateTemplateId id, CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
        public Task<bool> DeleteAsync(CertificateTemplateId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task<CertificateTemplate?> SetIssuancePolicyAsync(CertificateTemplateId id, IssuancePolicyId? policyId, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
        public Task<CertificateTemplate?> SetIssuerAsync(CertificateTemplateId id, IssuerId? issuerId, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
        public Task<CertificateTemplate?> SetPqcStageAsync(CertificateTemplateId id, PqcStage? stage, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<CertificateTemplate?>(null);
    }

    private sealed class NoopCertificateGenerator : ICertificateGenerator
    {
        public bool IsInitialized => true;
        public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
        public string GetCaCertificatePem() => "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----";
        public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => [];
        public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => [];
        public GeneratedCertificate GenerateCa(GenerateCaRequest request) => new();
        public void ImportCa(ImportCaRequest request) { }
        public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];
        public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null) => [];
    }
}
