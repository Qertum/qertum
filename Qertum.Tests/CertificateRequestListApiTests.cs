using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// The list route's server-side <c>status</c> and <c>search</c> filters and its companion
/// status-counts route, over real HTTP. The Web list pages page through these, so a filter that
/// only ran client-side would hide rows past the fetched page.
/// </summary>
public sealed class CertificateRequestListApiTests
{
    private const string ListRoute = "/v1/certificate-requests";
    private const string CountsRoute = "/v1/certificate-requests/status-counts";

    [Fact]
    public async Task List_StatusQuery_ReturnsOnlyThatStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("pending.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("issued.contoso.local", "bob@contoso.local", CertificateRequestStatus.Issued));
        using var client = Admin(factory);

        var page = await client.GetFromJsonAsync<PagedResult<CertificateRequest>>(
            $"{ListRoute}?status=Pending", ct);

        Assert.NotNull(page);
        Assert.Equal(1, page.TotalCount);
        Assert.Equal("pending.contoso.local", Assert.Single(page.Items).CommonName);
    }

    [Fact]
    public async Task List_SearchQuery_NarrowsToMatchingRows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("mail.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));
        using var client = Admin(factory);

        var page = await client.GetFromJsonAsync<PagedResult<CertificateRequest>>(
            $"{ListRoute}?search=api", ct);

        Assert.NotNull(page);
        Assert.Equal("api.contoso.local", Assert.Single(page.Items).CommonName);
    }

    [Fact]
    public async Task List_FilteredPagingReachesRowsBeyondTheFirstPage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var rows = Enumerable.Range(0, 120)
            .Select(i => ($"pending-{i:D3}.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending))
            .ToArray();
        await SeedAsync(factory, ct, rows);
        using var client = Admin(factory);

        var page = await client.GetFromJsonAsync<PagedResult<CertificateRequest>>(
            $"{ListRoute}?status=Pending&page=3&pageSize=50", ct);

        Assert.NotNull(page);
        Assert.Equal(120, page.TotalCount);
        Assert.Equal(20, page.Items.Count);
    }

    [Fact]
    public async Task StatusCounts_ReportsEveryStatusSeparately()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("a.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("b.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("c.contoso.local", "alice@contoso.local", CertificateRequestStatus.Revoked));
        using var client = Admin(factory);

        var counts = await client.GetFromJsonAsync<CertificateRequestStatusCounts>(CountsRoute, ct);

        Assert.NotNull(counts);
        Assert.Equal(3, counts.Total);
        Assert.Equal(2, counts.CountFor(CertificateRequestStatus.Pending));
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Revoked));
    }

    [Fact]
    public async Task StatusCounts_RequiresCertificatesView()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "counts-nobody", [AppPermissions.CertificatesCreate], ct);
        using var client = AsRole(factory, "counts-nobody");

        var response = await client.GetAsync(CountsRoute, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Client_PassesStatusAndSearchToTheServer()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("api.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("api.fabrikam.local", "alice@contoso.local", CertificateRequestStatus.Issued),
            ("mail.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));
        var client = new CertificateRequestsApiClient(Admin(factory));

        var page = await client.GetCertificateRequestsAsync(
            status: CertificateRequestStatus.Pending, search: "api", cancellationToken: ct);

        Assert.Equal(1, page.TotalCount);
        Assert.Equal("api.contoso.local", Assert.Single(page.Items).CommonName);
    }

    [Fact]
    public async Task Client_EncodesASearchTermContainingQueryDelimiters()
    {
        // "&" and "+" would otherwise split the query string or decode as a space server-side.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("a&b+c.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("plain.contoso.local", "bob@contoso.local", CertificateRequestStatus.Pending));
        var client = new CertificateRequestsApiClient(Admin(factory));

        var page = await client.GetCertificateRequestsAsync(search: "a&b+c", cancellationToken: ct);

        Assert.Equal("a&b+c.contoso.local", Assert.Single(page.Items).CommonName);
    }

    [Fact]
    public async Task Client_ReadsStatusCounts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct,
            ("a.contoso.local", "alice@contoso.local", CertificateRequestStatus.Pending),
            ("b.contoso.local", "alice@contoso.local", CertificateRequestStatus.Issued));
        var client = new CertificateRequestsApiClient(Admin(factory));

        var counts = await client.GetRequestStatusCountsAsync(cancellationToken: ct);

        Assert.Equal(2, counts.Total);
        Assert.Equal(1, counts.CountFor(CertificateRequestStatus.Pending));
    }

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
        return client;
    }

    private static async Task SeedRoleAsync(WebApplicationFactory<ApiServiceProgram> factory, string role,
        string[] permissions, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(permissions.Select(p => new RolePermission { Role = role, Permission = p }));
        await db.SaveChangesAsync(ct);
    }

    private static async Task SeedAsync(
        WebApplicationFactory<ApiServiceProgram> factory,
        CancellationToken ct,
        params (string CommonName, string RequestedBy, CertificateRequestStatus Status)[] rows)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var createdAt = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        foreach (var row in rows)
        {
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = row.CommonName,
                RequestedBy = row.RequestedBy,
                Status = row.Status,
                CreatedAtUtc = createdAt,
                UpdatedAtUtc = createdAt
            });
            createdAt = createdAt.AddMinutes(1);
        }

        await db.SaveChangesAsync(ct);
    }
}
