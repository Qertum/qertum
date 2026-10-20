using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Auth;

namespace Qertum.Tests;

file sealed class NoOpWebhookService : IWebhookService
{
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

file sealed class NoOpAuditLogService : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

/// <summary>
/// Regression tests for the former IMPROVEMENTS.md audit §3.1 — private keys were serialized into every
/// certificate-request response, including the list endpoint gated on the lowest permission.
/// </summary>
public sealed class PrivateKeyExposureTests
{
    private const string TestActor = "test-user";

    // ── Serialization ─────────────────────────────────────────────────────────

    [Fact]
    public void SerializedCertificateRequestOmitsPrivateKeys()
    {
        var request = new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----SECRET",
            PqcPrivateKeyPem = "-----BEGIN PRIVATE KEY-----PQCSECRET"
        };

        var json = JsonSerializer.Serialize(request);

        Assert.DoesNotContain("SECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("PQCSECRET", json, StringComparison.Ordinal);
        Assert.DoesNotContain("privateKeyPem", json, StringComparison.OrdinalIgnoreCase);
        // The public certificate must still be present — only key material is suppressed.
        Assert.Contains("BEGIN CERTIFICATE", json, StringComparison.Ordinal);
    }

    [Fact]
    public void DeserializedCertificateRequestIgnoresInboundPrivateKeys()
    {
        // A client must not be able to inject key material by posting it back.
        const string json = """{"commonName":"a.local","privateKeyPem":"INJECTED","pqcPrivateKeyPem":"INJECTED"}""";

        var request = JsonSerializer.Deserialize<CertificateRequest>(json);

        Assert.NotNull(request);
        Assert.Null(request.PrivateKeyPem);
        Assert.Null(request.PqcPrivateKeyPem);
    }

    // ── List projection ───────────────────────────────────────────────────────

    [Fact]
    public async Task ListResponsesCarryNoKeyMaterialButReportItsPresence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var created = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        await scope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----SECRET",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var page = await scope.Service.GetAllAsync(1, 100, cancellationToken: ct);
        var item = Assert.Single(page.Items);

        Assert.Null(item.PrivateKeyPem);
        Assert.True(item.HasPrivateKey);
        Assert.False(item.HasPqcPrivateKey);
    }

    [Fact]
    public async Task DashboardRecentRequestsCarryNoKeyMaterial()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var created = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        await scope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----SECRET",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var summary = await scope.Service.GetDashboardSummaryAsync(ct);

        Assert.All(summary.RecentRequests, r => Assert.Null(r.PrivateKeyPem));
    }

    [Fact]
    public async Task GetByIdStillLoadsTheKeySoTheDownloadEndpointCanServeIt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var created = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        await scope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----SECRET",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var loaded = await scope.Service.GetByIdAsync(created.Id, ct);

        Assert.NotNull(loaded);
        Assert.Equal("-----BEGIN PRIVATE KEY-----SECRET", loaded.PrivateKeyPem);
        Assert.True(loaded.HasPrivateKey);
    }

    [Fact]
    public async Task AcmeIssuedRequestReportsNoPrivateKey()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var created = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "acme.contoso.local",
            RequestedBy = "acme:1",
            Status = CertificateRequestStatus.Approved,
            CsrPem = "csr"
        }, TestActor, ct);

        // GenerateFromCsr returns an empty key: the ACME client holds it, the CA never sees it.
        await scope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----",
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var loaded = await scope.Service.GetByIdAsync(created.Id, ct);
        Assert.NotNull(loaded);
        Assert.False(loaded.HasPrivateKey);

        var page = await scope.Service.GetAllAsync(1, 100, cancellationToken: ct);
        Assert.False(Assert.Single(page.Items).HasPrivateKey);
    }

    // ── Ownership ─────────────────────────────────────────────────────────────

    [Fact]
    public void OwnerCanAccessTheirOwnKey()
    {
        var evaluator = CreateEvaluator();
        var request = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = "sub-alice" };

        Assert.True(evaluator.CanAccessPrivateKey(Principal(subject: "sub-alice"), request));
    }

    [Fact]
    public void NonOwnerCannotAccessAnotherUsersKey()
    {
        var evaluator = CreateEvaluator();
        var request = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = "sub-alice" };

        Assert.False(evaluator.CanAccessPrivateKey(Principal(subject: "sub-mallory"), request));
    }

    [Fact]
    public void CertificatesManageDoesNotGrantKeyAccess()
    {
        var evaluator = CreateEvaluator();
        var request = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = "sub-alice" };

        var manager = Principal(subject: "sub-mallory", roles: ["operator"]);

        Assert.False(evaluator.CanAccessPrivateKey(manager, request));
    }

    [Fact]
    public void AdminBypassesOwnership()
    {
        var evaluator = CreateEvaluator();
        var request = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = "sub-alice" };

        Assert.True(evaluator.CanAccessPrivateKey(Principal(subject: "sub-root", roles: ["admin"]), request));
    }

    [Fact]
    public void LegacyRowRequiresAdminEvenWhenDisplayNameMatches()
    {
        var evaluator = CreateEvaluator();
        var legacy = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = null };

        Assert.False(evaluator.CanAccessPrivateKey(Principal(subject: "sub-alice", name: "alice"), legacy));
        Assert.False(evaluator.CanAccessPrivateKey(Principal(subject: "sub-mallory", name: "mallory"), legacy));
        Assert.True(evaluator.CanAccessPrivateKey(Principal(subject: "sub-root", roles: ["admin"]), legacy));
    }

    [Fact]
    public void PrincipalWithoutSubjectCannotClaimAnOwnedRow()
    {
        var evaluator = CreateEvaluator();
        var request = new CertificateRequest { RequestedBy = "alice", RequestedBySubject = "sub-alice" };

        // No sub claim at all — must not match a row whose subject is set.
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity([new Claim("preferred_username", "alice")], "test"));

        Assert.False(evaluator.CanAccessPrivateKey(anonymous, request));
    }

    // ── Ownership propagation ─────────────────────────────────────────────────

    [Fact]
    public async Task RenewalInheritsOwnershipFromTheOriginal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var original = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            RequestedBySubject = "sub-alice",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        var renewal = await scope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.Equal("sub-alice", renewal.RequestedBySubject);
    }

    [Fact]
    public void CreateRequestDtoHasNoRequesterField()
    {
        // The requester is taken from the token. If the DTO ever regains the property, a caller
        // could file a request in someone else's name and this test should fail.
        Assert.Null(typeof(CreateCertificateRequestRequest).GetProperty("RequestedBy"));
        Assert.Null(typeof(UpdateCertificateRequestRequest).GetProperty("RequestedBy"));
    }

    [Fact]
    public void CreateRequestDtoHasNoStatusField()
    {
        // Every new request starts Pending. If the DTO ever regains Status, a caller with
        // certificates.create could file an already-Approved request and skip review.
        Assert.Null(typeof(CreateCertificateRequestRequest).GetProperty("Status"));
    }

    [Fact]
    public async Task UpdateDoesNotReassignOwnership()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();

        var created = await scope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice",
            RequestedBySubject = "sub-alice",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        var updated = await scope.Service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "mallory",
            RequestedBySubject = "sub-mallory",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        Assert.NotNull(updated);
        Assert.Equal("alice", updated.RequestedBy);
        Assert.Equal("sub-alice", updated.RequestedBySubject);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ICertificateAccessEvaluator CreateEvaluator() =>
        new CertificateAccessEvaluator(new IdentityClaimsMapper(new IdentityAuthenticationOptions
        {
            Authority = "https://idp.example",
            Audience = "qertum-api"
        }));

    private static ClaimsPrincipal Principal(string subject, string? name = null, string[]? roles = null)
    {
        var claims = new List<Claim> { new("sub", subject) };
        if (name is not null) claims.Add(new Claim("preferred_username", name));
        foreach (var role in roles ?? []) claims.Add(new Claim("role", role));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static async Task<Scope> CreateScopeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection)
            .Options;

        var dbContext = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        await dbContext.Database.EnsureCreatedAsync(ct);
        // The CA default is PQC stage Enforce; these tests issue RSA certificates, so they start from Off.
        dbContext.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await dbContext.SaveChangesAsync(ct);

        return new Scope(connection, dbContext,
            new CertificateRequestService(dbContext, new NoOpAuditLogService(), new NoOpWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(dbContext, new Qertum.Services.Policies.IssuancePolicyEvaluator())));
    }

    private sealed class Scope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        CertificateRequestService service) : IAsyncDisposable
    {
        public CertificateRequestService Service { get; } = service;

        public async ValueTask DisposeAsync()
        {
            await dbContext.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
