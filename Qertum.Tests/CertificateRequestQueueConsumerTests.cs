using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Tests;

file sealed class QueueNullWebhookService : IWebhookService
{
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

file sealed class QueueNullAuditLogService : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

file sealed class FakeCertificateGenerator : ICertificateGenerator
{

    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];

    public byte[] GenerateOcspResponse(
        byte[] derRequest,
        IReadOnlyDictionary<string, OcspCertificateStatus> statuses,
        CaSettings? caSettings = null) => [];
    private int _callCount;
    private readonly int _failUntilAttempt;

    public FakeCertificateGenerator(int failUntilAttempt = 0) =>
        _failUntilAttempt = failUntilAttempt;

    public int CallCount => _callCount;

    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
    {
        var attempt = Interlocked.Increment(ref _callCount);
        if (attempt <= _failUntilAttempt)
            throw new System.Security.Cryptography.CryptographicException($"Simulated failure #{attempt}");

        return new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
            ValidFrom = DateTime.UtcNow.AddMinutes(-5),
            ValidTo = DateTime.UtcNow.AddYears(1)
        };
    }

    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) =>
        [];

    public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) =>
        [];

    public bool IsInitialized => true;

    public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };

    public string GetCaCertificatePem() => "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----";

    public GeneratedCertificate GenerateCa(GenerateCaRequest request) => new()
    {
        CertificatePem = "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
        PrivateKeyPem = string.Empty,
        ValidFrom = DateTime.UtcNow,
        ValidTo = DateTime.UtcNow.AddYears(10)
    };

    public void ImportCa(ImportCaRequest request) { }

    public GeneratedCertificate GenerateFromCsr(
        string csrDerBase64Url,
        CertificateRequest request,
        CaSettings? caSettings,
        CertificateTemplate? template = null) =>
        GenerateCertificate(request, caSettings, template);
}

public sealed class CertificateRequestQueueConsumerTests
{
    [Fact]
    public async Task HappyPath_ApprovedRequest_TransitionsToIssued()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var request = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "happy.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);

        var generator = new FakeCertificateGenerator();
        await RunConsumerOnce(scope, generator, ct);

        var result = await scope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Issued, result.Status);
        Assert.NotNull(result.CertificatePem);
    }

    [Fact]
    public async Task TransientFailure_TwoFailuresThenSuccess_IssuedAfterThirdAttempt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var request = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "transient.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);

        var generator = new FakeCertificateGenerator(failUntilAttempt: 2);
        await RunConsumerOnce(scope, generator, ct);

        Assert.Equal(3, generator.CallCount);
        var result = await scope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Issued, result.Status);
    }

    [Fact]
    public async Task PermanentFailure_ThreeFailures_RequestRejectedWithReason()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var request = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "permanent-fail.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);

        var generator = new FakeCertificateGenerator(failUntilAttempt: 99); // always fails
        await RunConsumerOnce(scope, generator, ct);

        var result = await scope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Rejected, result.Status);
        Assert.NotNull(result.FailureReason);
        Assert.Contains("CryptographicException", result.FailureReason);
    }

    [Fact]
    public async Task StartupRecovery_StuckProcessingRow_ResetToApproved()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        // Seed a Processing row (simulating a crash mid-flight)
        var request = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "stuck.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);
        await scope.Service.DequeueNextApprovedAsync(ct); // moves to Processing

        var recovered = await scope.Service.ResetStuckProcessingAsync(ct);
        Assert.Equal(1, recovered);

        // ExecuteUpdate bypasses the change tracker; clear it so the next query reads fresh from DB.
        scope.DbContext.ChangeTracker.Clear();
        var result = await scope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Approved, result.Status);
    }

    [Fact]
    public async Task ConcurrentConsumers_SingleApprovedRow_ExactlyOneCertIssued()
    {
        var ct = TestContext.Current.CancellationToken;
        var scope = await CreateTestScopeAsync();

        await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "concurrent.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);

        // Spin up 5 concurrent consumers against the same DB
        var generator = new FakeCertificateGenerator();
        var sharedConnection = scope.Connection;
        var tasks = Enumerable.Range(0, 5).Select(async _ =>
        {
            var opts = new DbContextOptionsBuilder<CertificateRequestDbContext>()
                .UseSqlite(sharedConnection)
                .Options;
            var dataProtection = new EphemeralDataProtectionProvider();
            var db = new CertificateRequestDbContext(opts, dataProtection);
            var svc = new CertificateRequestService(db, new QueueNullAuditLogService(), new QueueNullWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(db, new Qertum.Services.Policies.IssuancePolicyEvaluator()));

            var dequeued = await svc.DequeueNextApprovedAsync(ct);
            if (dequeued is null) return false;

            var cert = generator.GenerateCertificate(dequeued, null);
            await svc.MarkAsIssuedAsync(dequeued.Id, cert, "concurrent-consumer", ct);
            return true;
        }).ToList();

        var results = await Task.WhenAll(tasks);
        Assert.Equal(1, results.Count(r => r)); // exactly one consumer issued the cert

        // Changes were made by separate DbContext instances; clear tracker to read fresh from DB.
        scope.DbContext.ChangeTracker.Clear();
        var all = await scope.Service.GetAllAsync(cancellationToken: ct);
        var issued = all.Items.Where(r => r.Status == CertificateRequestStatus.Issued).ToList();
        Assert.Single(issued);

        await scope.DisposeAsync();
    }

    [Fact]
    public async Task PolicyTightenedAfterApproval_IsRejectedWithoutCallingTheGenerator()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var request = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "outside.other.net",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, "test", ct);
        await Policies.PolicySeeding.LinkPublishedPolicyAsync(scope.DbContext, "WebServer",
            dnsSuffixes: ["corp.example.com"], ct: ct);

        var generator = new FakeCertificateGenerator();
        await RunConsumerOnce(scope, generator, ct);

        var result = await scope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Rejected, result.Status);
        Assert.Equal(0, generator.CallCount);
    }

    private static async Task RunConsumerOnce(QueueTestScope scope, ICertificateGenerator generator, CancellationToken ct)
    {
        var request = await scope.Service.DequeueNextApprovedAsync(ct);
        if (request is null) return;

        // Mirrors the real consumer: the policy is re-checked before anything is signed.
        var decision = await scope.Service.CheckIssuancePolicyAsync(request.Id, ct);
        if (!decision.Allowed) return;

        var settings = await scope.Service.GetSettingsAsync(ct);

        const int maxRetries = 3;
        string? failureReason = null;
        var issued = false;

        for (var attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                var cert = generator.GenerateCertificate(request, settings);
                await scope.Service.MarkAsIssuedAsync(request.Id, cert, "consumer", ct);
                issued = true;
                break;
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                failureReason = $"CryptographicException on attempt {attempt + 1}: {ex.Message}";
            }
        }

        if (!issued)
            await scope.Service.MarkAsRejectedWithReasonAsync(request.Id, failureReason, "consumer", ct);
    }

    private static async Task<QueueTestScope> CreateTestScopeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection)
            .Options;

        var dataProtection = new EphemeralDataProtectionProvider();
        var db = new CertificateRequestDbContext(options, dataProtection);
        await db.Database.EnsureCreatedAsync(ct);
        // The CA default is PQC stage Enforce; these tests issue RSA certificates, so they start from Off.
        db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await db.SaveChangesAsync(ct);

        return new QueueTestScope(connection, db, new CertificateRequestService(db, new QueueNullAuditLogService(), new QueueNullWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(db, new Qertum.Services.Policies.IssuancePolicyEvaluator())));
    }

    private sealed class QueueTestScope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        CertificateRequestService service) : IAsyncDisposable
    {
        public SqliteConnection Connection => connection;
        public CertificateRequestDbContext DbContext => dbContext;
        public CertificateRequestService Service => service;

        public async ValueTask DisposeAsync()
        {
            await dbContext.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
