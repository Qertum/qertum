using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Tests;

/// <summary>
/// Server-side status filtering, search and paging for the request list views. The Web list pages
/// used to fetch a single page of 100 and filter in the browser, so past 100 rows the Pending view
/// silently dropped requests and every chip count was wrong.
/// </summary>
public sealed class CertificateRequestListQueryTests
{
    [Fact]
    public async Task GetAllAsync_StatusFilter_ReturnsOnlyRequestsWithThatStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("pending-one.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("issued-one.contoso.local", "bob@contoso.local", CertificateRequestStatus.Issued),
            ("pending-two.contoso.local", "carol@contoso.local", CertificateRequestStatus.Pending));

        var result = await scope.Service.GetAllAsync(
            status: CertificateRequestStatus.Pending, cancellationToken: ct);

        Assert.Equal(2, result.TotalCount);
        Assert.All(result.Items, r => Assert.Equal(CertificateRequestStatus.Pending, r.Status));
    }

    [Fact]
    public async Task GetAllAsync_StatusFilter_ReachesRowsBeyondTheFirstPage()
    {
        // The bug: 120 Pending rows, a client page size of 50. Page 3 must hold the last 20 and
        // TotalCount must be the real 120, not what happened to fit in one fetch.
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        var rows = Enumerable.Range(0, 120)
            .Select(i => ($"pending-{i:D3}.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending))
            .ToArray();
        await SeedAsync(scope, rows);

        var lastPage = await scope.Service.GetAllAsync(
            page: 3, pageSize: 50, status: CertificateRequestStatus.Pending, cancellationToken: ct);

        Assert.Equal(120, lastPage.TotalCount);
        Assert.Equal(3, lastPage.TotalPages);
        Assert.Equal(20, lastPage.Items.Count);
    }

    [Fact]
    public async Task GetAllAsync_Search_MatchesCommonNameRegardlessOfCase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("API.Contoso.Local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("mail.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));

        var result = await scope.Service.GetAllAsync(search: "api", cancellationToken: ct);

        Assert.Equal("API.Contoso.Local", Assert.Single(result.Items).CommonName);
    }

    [Fact]
    public async Task GetAllAsync_Search_MatchesRequestedBy()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("mail.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));

        var result = await scope.Service.GetAllAsync(search: "BOB@", cancellationToken: ct);

        Assert.Equal("mail.contoso.local", Assert.Single(result.Items).CommonName);
    }

    [Fact]
    public async Task GetAllAsync_Search_TreatsUnderscoreAsALiteralCharacter()
    {
        // Unescaped, "_" is a single-character LIKE wildcard and would also match "api-one".
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("api_one.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("api-one.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));

        var result = await scope.Service.GetAllAsync(search: "api_one", cancellationToken: ct);

        Assert.Equal("api_one.contoso.local", Assert.Single(result.Items).CommonName);
    }

    [Fact]
    public async Task GetAllAsync_Search_TreatsPercentAsALiteralCharacter()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("mail.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));

        var result = await scope.Service.GetAllAsync(search: "%", cancellationToken: ct);

        Assert.Empty(result.Items);
    }

    [Fact]
    public async Task GetAllAsync_SearchAndStatus_ApplyTogether()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("api.fabrikam.local", "alice@contoso.local", CertificateRequestStatus.Issued));

        var result = await scope.Service.GetAllAsync(
            status: CertificateRequestStatus.Issued, search: "api", cancellationToken: ct);

        Assert.Equal("api.fabrikam.local", Assert.Single(result.Items).CommonName);
    }

    [Fact]
    public async Task GetStatusCountsAsync_CountsEachStatusSeparately()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("a.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("b.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("c.contoso.local", "alice@contoso.local", CertificateRequestStatus.Issued),
            ("d.contoso.local", "alice@contoso.local", CertificateRequestStatus.Revoked));

        var counts = await scope.Service.GetStatusCountsAsync(cancellationToken: ct);

        Assert.Equal(4, counts.Total);
        Assert.Equal(2, counts.CountFor(CertificateRequestStatus.Pending));
        // Unlike the dashboard summary, Revoked is counted on its own and not folded into Issued.
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Issued));
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Revoked));
        Assert.Equal(0, counts.CountFor(CertificateRequestStatus.Approved));
    }

    [Fact]
    public async Task GetStatusCountsAsync_CountsOnlyRowsMatchingTheSearch()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedAsync(scope,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("mail.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("api.fabrikam.local", "alice@contoso.local", CertificateRequestStatus.Issued));

        var counts = await scope.Service.GetStatusCountsAsync("api", ct);

        Assert.Equal(2, counts.Total);
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Pending));
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Issued));
    }

    [Fact]
    public async Task GetStatusCountsAsync_CountsAreExactBeyondOneHundredRows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        var rows = Enumerable.Range(0, 140)
            .Select(i => ($"pending-{i:D3}.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending))
            .ToArray();
        await SeedAsync(scope, rows);

        var counts = await scope.Service.GetStatusCountsAsync(cancellationToken: ct);

        Assert.Equal(140, counts.CountFor(CertificateRequestStatus.Pending));
    }

    [Theory]
    [InlineData(IssuedCertificateFilter.Valid, "valid.contoso.local")]
    [InlineData(IssuedCertificateFilter.Expiring, "expiring.contoso.local")]
    [InlineData(IssuedCertificateFilter.Expired, "expired.contoso.local")]
    [InlineData(IssuedCertificateFilter.Revoking, "revoking.contoso.local")]
    [InlineData(IssuedCertificateFilter.Revoked, "revoked.contoso.local")]
    public async Task GetIssuedAsync_ValidityFilter_SelectsOneBucket(IssuedCertificateFilter filter, string expected)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedIssuedAsync(scope);

        var result = await scope.Service.GetIssuedAsync(filter: filter, cancellationToken: ct);

        Assert.Equal(expected, Assert.Single(result.Items).CommonName);
    }

    [Fact]
    public async Task GetIssuedValidityCountsAsync_PutsEachCertificateInExactlyOneBucket()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedIssuedAsync(scope);

        var counts = await scope.Service.GetIssuedValidityCountsAsync(cancellationToken: ct);

        Assert.Equal(5, counts.Total);
        Assert.All(Enum.GetValues<IssuedCertificateFilter>(), f => Assert.Equal(1, counts.CountFor(f)));
    }

    [Fact]
    public async Task GetIssuedValidityCountsAsync_CountsOnlyRowsMatchingTheSearch()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateScopeAsync();
        await SeedIssuedAsync(scope);

        var counts = await scope.Service.GetIssuedValidityCountsAsync("revoked.", ct);

        Assert.Equal(1, counts.Total);
        Assert.Equal(1, counts.CountFor(IssuedCertificateFilter.Revoked));
        Assert.Equal(0, counts.CountFor(IssuedCertificateFilter.Valid));
    }

    /// <summary>One certificate in each validity bucket the certificates list offers.</summary>
    private static async Task SeedIssuedAsync(TestScope scope)
    {
        var ct = TestContext.Current.CancellationToken;
        var now = DateTime.UtcNow;
        var rows = new (string CommonName, CertificateRequestStatus Status, DateTime? ValidTo)[]
        {
            ("valid.contoso.local", CertificateRequestStatus.Issued, now.AddDays(200)),
            ("expiring.contoso.local", CertificateRequestStatus.Issued, now.AddDays(5)),
            ("expired.contoso.local", CertificateRequestStatus.Issued, now.AddDays(-1)),
            ("revoking.contoso.local", CertificateRequestStatus.PendingRevocation, now.AddDays(200)),
            ("revoked.contoso.local", CertificateRequestStatus.Revoked, now.AddDays(200)),
        };

        foreach (var row in rows)
        {
            scope.DbContext.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = row.CommonName,
                RequestedBy = "alice@contoso.local",
                Status = row.Status,
                ValidFrom = now.AddDays(-30),
                ValidTo = row.ValidTo,
                CreatedAtUtc = now.AddDays(-30),
                UpdatedAtUtc = now.AddDays(-30)
            });
        }

        await scope.DbContext.SaveChangesAsync(ct);
    }

    private static async Task SeedAsync(
        TestScope scope,
        params (string CommonName, string RequestedBy, CertificateRequestStatus Status)[] rows)
    {
        var ct = TestContext.Current.CancellationToken;
        var createdAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        foreach (var row in rows)
        {
            scope.DbContext.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = row.CommonName,
                RequestedBy = row.RequestedBy,
                Status = row.Status,
                CreatedAtUtc = createdAt,
                UpdatedAtUtc = createdAt
            });
            createdAt = createdAt.AddMinutes(1);
        }

        await scope.DbContext.SaveChangesAsync(ct);
    }

    private static async Task<TestScope> CreateScopeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection)
            .Options;

        var dbContext = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        await dbContext.Database.EnsureCreatedAsync(ct);

        var service = new CertificateRequestService(
            dbContext,
            new ListQueryNullAuditLogService(),
            new ListQueryNullWebhookService(),
            new Qertum.Services.Policies.IssuancePolicyService(
                dbContext, new Qertum.Services.Policies.IssuancePolicyEvaluator()));

        return new TestScope(connection, dbContext, service);
    }

    private sealed class TestScope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        CertificateRequestService service) : IAsyncDisposable
    {
        public CertificateRequestDbContext DbContext { get; } = dbContext;

        public CertificateRequestService Service { get; } = service;

        public async ValueTask DisposeAsync()
        {
            await DbContext.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}

file sealed class ListQueryNullAuditLogService : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

file sealed class ListQueryNullWebhookService : IWebhookService
{
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}
