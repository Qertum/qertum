using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests;

/// <summary>
/// Onboarding's "Generate" only files a Root CA request; the CA exists once that request is approved.
/// Until then nothing can be signed, so a request filed in the meantime could only ever be rejected —
/// by the approve endpoint, or by the consumer after it has burned its retries. These pin the refusal
/// at the point of creation instead, for every path that inserts a row (REST, renewal, ACME, EST).
/// </summary>
public sealed class CaNotInitializedGuardTests
{
    [Fact]
    public async Task CreateAsync_WithoutACa_IsRefused()
    {
        await using var scope = await TestScope.CreateAsync(caInitialized: false);

        await Assert.ThrowsAsync<CaNotInitializedException>(() => scope.Service.CreateAsync(
            new CertificateRequest { CommonName = "web.contoso.com", Type = "WebServer", RequestedBy = "alice" },
            "alice", TestContext.Current.CancellationToken));

        Assert.Empty(await scope.Db.CertificateRequests.ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CreateAsync_ForTheRootCaItself_IsAllowed()
    {
        await using var scope = await TestScope.CreateAsync(caInitialized: false);

        var created = await scope.Service.CreateAsync(
            new CertificateRequest
            {
                CommonName = "Contoso Root",
                Type = WellKnownCertificateTypes.RootCa,
                RequestedBy = "admin"
            },
            "admin", TestContext.Current.CancellationToken);

        Assert.Equal(CertificateRequestStatus.Pending, created.Status);
    }

    [Fact]
    public async Task CreateAsync_OnceTheCaExists_IsAllowed()
    {
        await using var scope = await TestScope.CreateAsync(caInitialized: true);

        var created = await scope.Service.CreateAsync(
            new CertificateRequest { CommonName = "web.contoso.com", Type = "WebServer", RequestedBy = "alice" },
            "alice", TestContext.Current.CancellationToken);

        Assert.Equal("web.contoso.com", created.CommonName);
    }

    [Fact]
    public async Task RenewAsync_WithoutACa_IsRefused()
    {
        // RenewAsync inserts its row directly rather than through CreateAsync, so it needs its own check.
        await using var scope = await TestScope.CreateAsync(caInitialized: true);
        var issued = await scope.Service.CreateAsync(
            new CertificateRequest { CommonName = "web.contoso.com", Type = "WebServer", RequestedBy = "alice" },
            "alice", TestContext.Current.CancellationToken);

        scope.Generator.IsInitialized = false;

        await Assert.ThrowsAsync<CaNotInitializedException>(() =>
            scope.Service.RenewAsync(issued.Id, "alice", TestContext.Current.CancellationToken));
    }

    private sealed class TestScope(
        SqliteConnection connection,
        CertificateRequestDbContext db,
        CertificateRequestService service,
        FakeGenerator generator) : IAsyncDisposable
    {
        public CertificateRequestDbContext Db { get; } = db;

        public CertificateRequestService Service { get; } = service;

        public FakeGenerator Generator { get; } = generator;

        public static async Task<TestScope> CreateAsync(bool caInitialized)
        {
            var connection = new SqliteConnection("DataSource=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);

            var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
            await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            // The CA default is PQC stage Enforce; these tests issue RSA certificates, so they start from Off.
            db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);

            var generator = new FakeGenerator { IsInitialized = caInitialized };
            var service = new CertificateRequestService(
                db,
                new GuardNullAuditLogService(),
                new GuardNullWebhookService(),
                new IssuancePolicyService(db, new IssuancePolicyEvaluator()),
                generator);

            return new TestScope(connection, db, service, generator);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    /// <summary>Only <see cref="IsInitialized"/> matters here; nothing else is reached.</summary>
    private sealed class FakeGenerator : ICertificateGenerator
    {
        public bool IsInitialized { get; set; }

        public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
            => throw new NotSupportedException();

        public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
            => throw new NotSupportedException();

        public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null)
            => throw new NotSupportedException();

        public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null)
            => throw new NotSupportedException();

        public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => throw new NotSupportedException();

        public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null)
            => throw new NotSupportedException();

        public CaStatusResponse GetCaStatus() => new() { IsInitialized = IsInitialized };

        public string GetCaCertificatePem() => throw new NotSupportedException();

        public GeneratedCertificate GenerateCa(GenerateCaRequest request) => throw new NotSupportedException();

        public void ImportCa(ImportCaRequest request) => throw new NotSupportedException();
    }

    private sealed class GuardNullAuditLogService : IAuditLogService
    {
        public Task LogAsync(string action, string performedBy, Guid? resourceId = null, string? resourceName = null,
            string? detail = null, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }

    private sealed class GuardNullWebhookService : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<Webhook>>([]);

        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default)
            => Task.FromResult<Webhook?>(null);

        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default)
            => Task.FromResult(webhook);

        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default)
            => Task.FromResult<Webhook?>(null);

        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default)
            => Task.FromResult(false);

        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }
}
