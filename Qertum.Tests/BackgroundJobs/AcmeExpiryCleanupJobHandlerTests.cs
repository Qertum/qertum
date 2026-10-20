using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Acme;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace Qertum.Tests.BackgroundJobs;

public sealed class AcmeExpiryCleanupJobHandlerTests
{
    [Fact]
    public async Task Sweep_RemovesOrdersPastRetentionWithTheirAuthorizationsAndChallenges()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CleanupScope.CreateAsync();

        var stale = await scope.AddOrderAsync("stale.contoso.local", DateTime.UtcNow.AddDays(-30), ct);
        var recentlyExpired = await scope.AddOrderAsync("recent.contoso.local", DateTime.UtcNow.AddHours(-1), ct);
        var live = await scope.AddOrderAsync("live.contoso.local", DateTime.UtcNow.AddDays(3), ct);

        var removed = await scope.CreateService().SweepAsync(ct);

        Assert.Equal(1, removed);

        await using var db = scope.NewDbContext();
        Assert.Null(await db.AcmeOrders.FindAsync([stale], ct));
        Assert.NotNull(await db.AcmeOrders.FindAsync([recentlyExpired], ct));
        Assert.NotNull(await db.AcmeOrders.FindAsync([live], ct));

        // The rows hanging off the deleted order go with it; nothing is left orphaned.
        Assert.Empty(await db.AcmeAuthorizations.Where(a => a.OrderId == stale).ToListAsync(ct));
        Assert.Equal(2, await db.AcmeAuthorizations.CountAsync(ct));
        Assert.Equal(2, await db.AcmeChallenges.CountAsync(ct));
    }

    [Fact]
    public async Task Sweep_LeavesTheCertificateRequestBehind()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CleanupScope.CreateAsync();

        var certRequestId = new CertificateRequestId(Guid.NewGuid());
        await scope.AddOrderAsync("issued.contoso.local", DateTime.UtcNow.AddDays(-30), ct,
            certificateRequestId: certRequestId);

        await using (var seed = scope.NewDbContext())
        {
            seed.CertificateRequests.Add(new CertificateRequest
            {
                Id = certRequestId,
                CommonName = "issued.contoso.local",
                RequestedBy = "acme:test",
                Status = CertificateRequestStatus.Issued
            });
            await seed.SaveChangesAsync(ct);
        }

        await scope.CreateService().SweepAsync(ct);

        // The order is an ACME protocol artifact; the certificate record outlives it.
        await using var db = scope.NewDbContext();
        Assert.Empty(await db.AcmeOrders.ToListAsync(ct));
        Assert.NotNull(await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == certRequestId, ct));
    }

    [Fact]
    public async Task Sweep_HonoursTheBatchSize()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CleanupScope.CreateAsync();

        for (var i = 0; i < 3; i++)
            await scope.AddOrderAsync($"old{i}.contoso.local", DateTime.UtcNow.AddDays(-30 - i), ct);

        var service = scope.CreateService(new AcmeExpiryCleanupOptions { BatchSize = 2 });

        Assert.Equal(2, await service.SweepAsync(ct));
        Assert.Equal(1, await service.SweepAsync(ct));
        Assert.Equal(0, await service.SweepAsync(ct));
    }

    private sealed class CleanupScope : IAsyncDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly List<CertificateRequestDbContext> _contexts = [];

        private CleanupScope(SqliteConnection connection) => _connection = connection;

        public static async Task<CleanupScope> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync(TestContext.Current.CancellationToken);

            var scope = new CleanupScope(connection);
            await using var db = scope.NewDbContext();
            await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
            return scope;
        }

        public CertificateRequestDbContext NewDbContext() =>
            new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(_connection).Options,
                new EphemeralDataProtectionProvider());

        public AcmeExpiryCleanupJobHandler CreateService(AcmeExpiryCleanupOptions? options = null)
        {
            var db = NewDbContext();
            _contexts.Add(db);
            return new(db, Options.Create(options ?? new AcmeExpiryCleanupOptions()),
                NullLogger<AcmeExpiryCleanupJobHandler>.Instance);
        }

        public async Task<Guid> AddOrderAsync(
            string domain, DateTime expiresAtUtc, CancellationToken ct,
            CertificateRequestId? certificateRequestId = null)
        {
            await using var db = NewDbContext();

            var account = new AcmeAccount { JwkThumbprint = Guid.NewGuid().ToString("N"), PublicKeyJwk = "{}" };
            var order = new AcmeOrder
            {
                Account = account,
                IdentifiersJson = $"[{{\"type\":\"dns\",\"value\":\"{domain}\"}}]",
                ExpiresAtUtc = expiresAtUtc,
                CertificateRequestId = certificateRequestId is { } id ? (Guid)id : null
            };
            var authorization = new AcmeAuthorization
            {
                Order = order,
                IdentifierValue = domain,
                ExpiresAtUtc = expiresAtUtc
            };
            db.AcmeChallenges.Add(new AcmeChallenge
            {
                Authorization = authorization,
                Token = Guid.NewGuid().ToString("N")
            });
            await db.SaveChangesAsync(ct);
            return order.Id;
        }

        public async ValueTask DisposeAsync()
        {
            foreach (var db in _contexts) await db.DisposeAsync();
            await _connection.DisposeAsync();
        }
    }
}
