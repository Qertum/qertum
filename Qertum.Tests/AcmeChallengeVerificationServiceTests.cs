using System.Diagnostics;
using Qertum.AcmeService;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Qertum.Tests;

/// <summary>
/// Records which domains were attempted and answers per-domain, so a test can tell an
/// unreachable domain apart from a healthy one inside a single verification pass.
/// </summary>
file sealed class ScriptedVerifier(params string[] succeedingDomains) : IAcmeChallengeVerifier
{
    private readonly HashSet<string> _succeeding = [.. succeedingDomains];
    private readonly List<string> _attempted = [];

    public IReadOnlyList<string> Attempted
    {
        get { lock (_attempted) return [.. _attempted]; }
    }

    public Task<AcmeVerificationResult> VerifyHttp01Async(
        string domain, string token, string accountKeyThumbprint, CancellationToken ct = default)
    {
        lock (_attempted) _attempted.Add(domain);

        return Task.FromResult(_succeeding.Contains(domain)
            ? AcmeVerificationResult.Valid
            : AcmeVerificationResult.Failed(AcmeChallengeFailure.ConnectionFailed, "connection refused"));
    }

    public Task<AcmeVerificationResult> VerifyDns01Async(
        string baseDomain, string token, string accountKeyThumbprint, CancellationToken ct = default)
    {
        lock (_attempted) _attempted.Add($"dns:{baseDomain}");

        return Task.FromResult(_succeeding.Contains(baseDomain)
            ? AcmeVerificationResult.Valid
            : AcmeVerificationResult.Failed(AcmeChallengeFailure.DnsNoTxtRecord, "no TXT record"));
    }
}

public sealed class AcmeChallengeVerificationServiceTests
{
    [Fact]
    public async Task OneFailingDomain_DoesNotStallTheOtherChallengesInThePass()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("broken.contoso.local", ct);
        await scope.AddChallengeAsync("healthy.contoso.local", ct);

        var verifier = new ScriptedVerifier("healthy.contoso.local");
        var service = scope.CreateService(verifier);

        var stopwatch = Stopwatch.StartNew();
        await service.ProcessPendingChallengesAsync(ct);
        stopwatch.Stop();

        // Both domains are attempted in the same pass. Before the fix, the failing one slept for the
        // retry delay inside the loop, so a single unreachable domain held up every other challenge.
        Assert.Contains("broken.contoso.local", verifier.Attempted);
        Assert.Contains("healthy.contoso.local", verifier.Attempted);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2),
            $"Verification pass must not block on a failed challenge, but took {stopwatch.Elapsed}.");

        await using var verify = scope.NewDbContext();
        var healthy = await verify.AcmeChallenges.AsNoTracking()
            .SingleAsync(c => c.Authorization.IdentifierValue == "healthy.contoso.local", ct);
        Assert.Equal("valid", healthy.Status);
    }

    [Fact]
    public async Task FailedAttempt_SchedulesTheRetryInsteadOfSleeping()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("broken.contoso.local", ct);

        var before = DateTime.UtcNow;
        var service = scope.CreateService(new ScriptedVerifier());
        await service.ProcessPendingChallengesAsync(ct);

        await using var verify = scope.NewDbContext();
        var challenge = await verify.AcmeChallenges.AsNoTracking().SingleAsync(ct);

        Assert.Equal("processing", challenge.Status);
        Assert.Equal(1, challenge.ValidationAttempts);
        Assert.True(challenge.NextAttemptAfterUtc > before,
            "A failed attempt must push the next attempt into the future.");
    }

    [Fact]
    public async Task ChallengeNotYetDue_IsNotAttempted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("later.contoso.local", ct,
            nextAttemptAfterUtc: DateTime.UtcNow.AddMinutes(5));

        var verifier = new ScriptedVerifier("later.contoso.local");
        var service = scope.CreateService(verifier);
        await service.ProcessPendingChallengesAsync(ct);

        Assert.Empty(verifier.Attempted);

        await using var verify = scope.NewDbContext();
        var challenge = await verify.AcmeChallenges.AsNoTracking().SingleAsync(ct);
        Assert.Equal(0, challenge.ValidationAttempts);
        Assert.Equal("processing", challenge.Status);
    }

    [Fact]
    public async Task AttemptsAreExhausted_MarksTheChallengeInvalid()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("broken.contoso.local", ct);

        var service = scope.CreateService(new ScriptedVerifier());

        // Each pass takes one attempt; the scheduled retry is cleared between passes so the test
        // does not have to wait out the real back-off.
        for (var i = 0; i < 3; i++)
        {
            await service.ProcessPendingChallengesAsync(ct);
            await using var reset = scope.NewDbContext();
            await reset.AcmeChallenges.ExecuteUpdateAsync(
                s => s.SetProperty(c => c.NextAttemptAfterUtc, DateTime.UtcNow.AddMinutes(-1)), ct);
        }

        await using var verify = scope.NewDbContext();
        var challenge = await verify.AcmeChallenges.AsNoTracking().SingleAsync(ct);

        Assert.Equal("invalid", challenge.Status);
        Assert.Equal(3, challenge.ValidationAttempts);
        Assert.NotNull(challenge.ErrorJson);
    }

    [Fact]
    public async Task OneValidChallenge_PromotesTheAuthorizationEvenWithAPendingSibling()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        var authId = await scope.AddChallengeAsync("dual.contoso.local", ct, type: "dns-01");
        await scope.AddSiblingChallengeAsync(authId, ct, "http-01", "pending");

        var service = scope.CreateService(new ScriptedVerifier("dual.contoso.local"));
        await service.ProcessPendingChallengesAsync(ct);

        await using var verify = scope.NewDbContext();
        var auth = await verify.AcmeAuthorizations.AsNoTracking().SingleAsync(ct);
        var order = await verify.AcmeOrders.AsNoTracking().SingleAsync(ct);

        // The client chose dns-01 and passed. The http-01 challenge it never touched must not
        // hold the authorization back — nothing will ever move a "pending" challenge.
        Assert.Equal("valid", auth.Status);
        Assert.Equal("ready", order.Status);
    }

    [Fact]
    public async Task AFailedChallenge_DoesNotInvalidateTheAuthorizationWhileASiblingIsViable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        var authId = await scope.AddChallengeAsync("broken.contoso.local", ct, type: "dns-01");
        await scope.AddSiblingChallengeAsync(authId, ct, "http-01", "pending");

        var service = scope.CreateService(new ScriptedVerifier());

        for (var i = 0; i < 3; i++)
        {
            await service.ProcessPendingChallengesAsync(ct);
            await using var reset = scope.NewDbContext();
            await reset.AcmeChallenges
                .Where(c => c.Type == "dns-01")
                .ExecuteUpdateAsync(
                    s => s.SetProperty(c => c.NextAttemptAfterUtc, DateTime.UtcNow.AddMinutes(-1)), ct);
        }

        await using var verify = scope.NewDbContext();
        var dns = await verify.AcmeChallenges.AsNoTracking().SingleAsync(c => c.Type == "dns-01", ct);
        var auth = await verify.AcmeAuthorizations.AsNoTracking().SingleAsync(ct);
        var order = await verify.AcmeOrders.AsNoTracking().SingleAsync(ct);

        Assert.Equal("invalid", dns.Status);
        Assert.Equal("pending", auth.Status);
        Assert.Equal("pending", order.Status);
    }

    [Fact]
    public async Task AFailedChallenge_InvalidatesTheAuthorizationWhenNoSiblingRemains()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        var authId = await scope.AddChallengeAsync("broken.contoso.local", ct, type: "dns-01");
        await scope.AddSiblingChallengeAsync(authId, ct, "http-01", "invalid");

        var service = scope.CreateService(new ScriptedVerifier());

        for (var i = 0; i < 3; i++)
        {
            await service.ProcessPendingChallengesAsync(ct);
            await using var reset = scope.NewDbContext();
            await reset.AcmeChallenges
                .Where(c => c.Type == "dns-01")
                .ExecuteUpdateAsync(
                    s => s.SetProperty(c => c.NextAttemptAfterUtc, DateTime.UtcNow.AddMinutes(-1)), ct);
        }

        await using var verify = scope.NewDbContext();
        var auth = await verify.AcmeAuthorizations.AsNoTracking().SingleAsync(ct);
        var order = await verify.AcmeOrders.AsNoTracking().SingleAsync(ct);

        Assert.Equal("invalid", auth.Status);
        Assert.Equal("invalid", order.Status);
    }

    [Fact]
    public async Task Metrics_CountChallengeAttemptsByTypeOutcomeAndFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, ProtocolMetrics.MeterName);
        using var metrics = new ProtocolMetrics(meters);

        await scope.AddChallengeAsync("healthy.contoso.local", ct);
        await scope.AddChallengeAsync("broken.contoso.local", ct, type: "dns-01");
        var service = scope.CreateService(new ScriptedVerifier("healthy.contoso.local"), metrics: metrics);

        await service.ProcessPendingChallengesAsync(ct);

        Assert.Equal(1, recorder.Sum("ca.acme.challenges", ("type", "http-01"), ("outcome", "valid"), ("failure", "None")));
        Assert.Equal(1, recorder.Sum("ca.acme.challenges", ("type", "dns-01"), ("outcome", "retry"), ("failure", "DnsNoTxtRecord")));
    }

    [Fact]
    public async Task Metrics_CountAnExhaustedChallengeAsFailedAndItsOrderAsInvalid()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, ProtocolMetrics.MeterName);
        using var metrics = new ProtocolMetrics(meters);

        await scope.AddChallengeAsync("broken.contoso.local", ct);
        var service = scope.CreateService(new ScriptedVerifier(), metrics: metrics);

        for (var i = 0; i < 3; i++)
        {
            await service.ProcessPendingChallengesAsync(ct);
            await using var reset = scope.NewDbContext();
            await reset.AcmeChallenges.ExecuteUpdateAsync(
                s => s.SetProperty(c => c.NextAttemptAfterUtc, DateTime.UtcNow.AddMinutes(-1)), ct);
        }

        Assert.Equal(2, recorder.Sum("ca.acme.challenges", ("outcome", "retry")));
        Assert.Equal(1, recorder.Sum("ca.acme.challenges", ("outcome", "failed"), ("failure", "ConnectionFailed")));
        Assert.Equal(1, recorder.Sum("ca.acme.orders", ("outcome", "invalid")));
    }

    [Fact]
    public async Task ChallengeType_SelectsTheVerificationMethod()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("http.contoso.local", ct, type: "http-01");
        await scope.AddChallengeAsync("dns.contoso.local", ct, type: "dns-01");

        var verifier = new ScriptedVerifier();
        var service = scope.CreateService(verifier);

        await service.ProcessPendingChallengesAsync(ct);

        // ScriptedVerifier prefixes dns-01 attempts, so this shows which method each row reached.
        Assert.Contains("http.contoso.local", verifier.Attempted);
        Assert.Contains("dns:dns.contoso.local", verifier.Attempted);
    }

    [Fact]
    public async Task AnUnknownChallengeType_FailsRatherThanFallingBackToHttp()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AcmeVerificationScope.CreateAsync();

        await scope.AddChallengeAsync("alpn.contoso.local", ct, type: "tls-alpn-01");

        var verifier = new ScriptedVerifier("alpn.contoso.local");
        var service = scope.CreateService(verifier);

        await service.ProcessPendingChallengesAsync(ct);

        Assert.Empty(verifier.Attempted);

        await using var verify = scope.NewDbContext();
        var challenge = await verify.AcmeChallenges.AsNoTracking().SingleAsync(ct);
        Assert.Equal(1, challenge.ValidationAttempts);
        Assert.Equal("processing", challenge.Status);
    }

    /// <summary>Owns an in-memory SQLite database and the scope factory the service resolves from.</summary>
    private sealed class AcmeVerificationScope : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;

        private AcmeVerificationScope(SqliteConnection connection) => _connection = connection;

        public static async Task<AcmeVerificationScope> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);

            var scope = new AcmeVerificationScope(connection);
            await using var db = scope.NewDbContext();
            await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return scope;
        }

        public CertificateRequestDbContext NewDbContext() =>
            new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(_connection).Options,
                new EphemeralDataProtectionProvider());

        public AcmeChallengeVerificationService CreateService(IAcmeChallengeVerifier verifier,
            IDiagnosticEventLog? diagnostics = null, ProtocolMetrics? metrics = null) =>
            new(new SingleDbContextScopeFactory(NewDbContext), verifier,
                diagnostics ?? new Lifecycle.RecordingDiagnosticEventLog(),
                NullLogger<AcmeChallengeVerificationService>.Instance, metrics);

        public async Task<Guid> AddChallengeAsync(
            string domain,
            CancellationToken ct,
            DateTime? nextAttemptAfterUtc = null,
            string type = "http-01")
        {
            await using var db = NewDbContext();

            var account = new AcmeAccount { JwkThumbprint = Guid.NewGuid().ToString("N"), PublicKeyJwk = "{}" };
            var order = new AcmeOrder
            {
                Account = account,
                IdentifiersJson = $"[{{\"type\":\"dns\",\"value\":\"{domain}\"}}]",
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var authorization = new AcmeAuthorization
            {
                Order = order,
                IdentifierValue = domain,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(1)
            };
            var challenge = new AcmeChallenge
            {
                Authorization = authorization,
                Type = type,
                Token = Guid.NewGuid().ToString("N"),
                Status = "processing"
            };

            if (nextAttemptAfterUtc.HasValue)
                challenge.NextAttemptAfterUtc = nextAttemptAfterUtc.Value;

            db.AcmeChallenges.Add(challenge);
            await db.SaveChangesAsync(ct);
            return authorization.Id;
        }

        /// <summary>Attaches a second challenge to an authorization that already exists.</summary>
        public async Task AddSiblingChallengeAsync(
            Guid authorizationId, CancellationToken ct, string type, string status)
        {
            await using var db = NewDbContext();

            db.AcmeChallenges.Add(new AcmeChallenge
            {
                AuthorizationId = authorizationId,
                Type = type,
                Token = Guid.NewGuid().ToString("N"),
                Status = status
            });
            await db.SaveChangesAsync(ct);
        }

        public async ValueTask DisposeAsync() => await _connection.DisposeAsync();
    }

    /// <summary>Minimal IServiceScopeFactory handing out one fresh DbContext per scope.</summary>
    private sealed class SingleDbContextScopeFactory(Func<CertificateRequestDbContext> factory)
        : IServiceScopeFactory, IServiceScope, IServiceProvider
    {
        private CertificateRequestDbContext? _current;

        public IServiceScope CreateScope()
        {
            _current = factory();
            return this;
        }

        public IServiceProvider ServiceProvider => this;

        public object? GetService(Type serviceType) =>
            serviceType == typeof(CertificateRequestDbContext) ? _current : null;

        public void Dispose() => _current?.Dispose();
    }
}
