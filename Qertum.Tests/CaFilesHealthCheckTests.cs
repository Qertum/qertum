using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Qertum.Services;

namespace Qertum.Tests;

// Fake generator: readiness is asked of ICertificateGenerator.IsInitialized rather than the
// health check touching disk itself — that's the seam a future non-file (vault/HSM) signer
// would report through, unchanged.
internal sealed class FakeCertificateGenerator : ICertificateGenerator
{
    public bool IsInitialized { get; set; }

    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => throw new NotSupportedException();
    public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => throw new NotSupportedException();
    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => throw new NotSupportedException();
    public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => throw new NotSupportedException();
    public GeneratedCertificate GenerateCa(GenerateCaRequest request) => throw new NotSupportedException();
    public void ImportCa(ImportCaRequest request) => throw new NotSupportedException();
    public CaStatusResponse GetCaStatus() => throw new NotSupportedException();
    public string GetCaCertificatePem() => throw new NotSupportedException();
    public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null) => throw new NotSupportedException();
    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => throw new NotSupportedException();
}

public sealed class CaFilesHealthCheckTests
{
    [Fact]
    public async Task NoCaSettings_ReportsHealthy_OnboardingNotStarted()
    {
        await using var scope = await Scope.CreateAsync();

        var result = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("not yet completed", result.Description);
    }

    [Fact]
    public async Task CaSettingsExists_GeneratorInitialized_ReportsHealthy()
    {
        await using var scope = await Scope.CreateAsync();
        await scope.SeedCaSettingsAsync();
        scope.Generator.IsInitialized = true;

        var result = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task CaSettingsExists_NotInitialized_RootCaRequestPending_ReportsHealthy()
    {
        // Approval is a manual step and can take a long time — this must not flap Unhealthy
        // while waiting on it, however long it takes.
        await using var scope = await Scope.CreateAsync();
        await scope.SeedCaSettingsAsync();
        await scope.SeedRootCaRequestAsync(CertificateRequestStatus.Pending);
        scope.Generator.IsInitialized = false;

        var result = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, result.Status);
        Assert.Contains("in progress", result.Description);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Approved)]
    [InlineData(CertificateRequestStatus.Processing)]
    public async Task CaSettingsExists_NotInitialized_RootCaRequestInFlight_ReportsHealthy(CertificateRequestStatus status)
    {
        await using var scope = await Scope.CreateAsync();
        await scope.SeedCaSettingsAsync();
        await scope.SeedRootCaRequestAsync(status);
        scope.Generator.IsInitialized = false;

        var result = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Fact]
    public async Task CaSettingsExists_NotInitialized_NoRequestInFlight_ReportsUnhealthy()
    {
        // Was ready (CaSettings exists) and now isn't, with nothing in flight to explain it —
        // files removed, or a non-file backend went unreachable. Must fire immediately, no
        // grace-period timer.
        await using var scope = await Scope.CreateAsync();
        await scope.SeedCaSettingsAsync();
        scope.Generator.IsInitialized = false;

        var result = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
    }

    [Fact]
    public async Task ResultIsCachedForSixtySeconds()
    {
        await using var scope = await Scope.CreateAsync();
        await scope.SeedCaSettingsAsync();
        scope.Generator.IsInitialized = false;

        var first = await scope.CheckHealthAsync();
        Assert.Equal(HealthStatus.Unhealthy, first.Status);

        // Flip to ready without clearing the cache — a cached Unhealthy must not update
        // instantaneously; that's the 60s poll-noise reduction, unrelated to the grace period
        // that was removed.
        scope.Generator.IsInitialized = true;
        var second = await scope.CheckHealthAsync();

        Assert.Equal(HealthStatus.Unhealthy, second.Status);
    }

    private sealed class Scope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        FakeCertificateGenerator generator,
        CaFilesHealthCheck healthCheck) : IAsyncDisposable
    {
        public FakeCertificateGenerator Generator { get; } = generator;

        public Task<HealthCheckResult> CheckHealthAsync() =>
            healthCheck.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

        public async Task SeedCaSettingsAsync()
        {
            dbContext.Settings.Add(new CaSettings { PqcStage = PqcStage.Off });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        public async Task SeedRootCaRequestAsync(CertificateRequestStatus status)
        {
            dbContext.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "Test Root CA",
                RequestedBy = "test-admin",
                Type = WellKnownCertificateTypes.RootCa,
                Status = status
            });
            await dbContext.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        public async ValueTask DisposeAsync()
        {
            await dbContext.DisposeAsync();
            await connection.DisposeAsync();
        }

        public static async Task<Scope> CreateAsync()
        {
            var ct = TestContext.Current.CancellationToken;
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(ct);

            var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
                .UseSqlite(connection)
                .Options;

            var dbContext = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
            await dbContext.Database.EnsureCreatedAsync(ct);

            var generator = new FakeCertificateGenerator();

            var services = new ServiceCollection();
            services.AddSingleton(dbContext);
            services.AddScoped<ICertificateRequestService>(_ =>
                new CertificateRequestService(dbContext, new NoOpAuditLogService(), new NoOpWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(dbContext, new Qertum.Services.Policies.IssuancePolicyEvaluator())));
            var provider = services.BuildServiceProvider();

            var healthCheck = new CaFilesHealthCheck(
                provider.GetRequiredService<IServiceScopeFactory>(),
                generator,
                new CaDataOptions { Directory = Path.GetTempPath() },
                new MemoryCache(new MemoryCacheOptions()));

            return new Scope(connection, dbContext, generator, healthCheck);
        }
    }

    private sealed class NoOpWebhookService : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NoOpAuditLogService : IAuditLogService
    {
        public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }
}
