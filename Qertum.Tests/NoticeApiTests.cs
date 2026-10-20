using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class NoticeApiTests
{
    private sealed class Arranged(WebApplicationFactory<ApiServiceProgram> factory) : IAsyncDisposable
    {
        public WebApplicationFactory<ApiServiceProgram> Factory { get; } = factory;

        public HttpClient As(string? role)
        {
            var client = Factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = role is null
                ? new AuthenticationHeaderValue("Test")
                : new AuthenticationHeaderValue("Test-Role", role);
            return client;
        }

        public ValueTask DisposeAsync() => Factory.DisposeAsync();
    }

    // Roles: viewer = certificates.view, creator = certificates.create only.
    private static async Task<Arranged> ArrangeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(
            new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "creator", Permission = AppPermissions.CertificatesCreate });
        var withContact = new CertificateRequest
        {
            CommonName = "contact.contoso.local", RequestedBy = "alice", Status = CertificateRequestStatus.Issued,
            ValidTo = DateTime.UtcNow.AddDays(10),
            Metadata = new CertificateMetadata { OwnerTeam = "Platform", ContactEmail = "ops@contoso.local" }
        };
        var bare = new CertificateRequest
        {
            CommonName = "bare.contoso.local", RequestedBy = "alice", Status = CertificateRequestStatus.Issued,
            ValidTo = DateTime.UtcNow.AddDays(5)
        };
        db.CertificateRequests.AddRange(withContact, bare);
        db.Notices.AddRange(
            new Notice { RequestId = withContact.Id, Kind = NoticeKind.Expiring, Step = 14, CreatedAtUtc = DateTime.UtcNow.AddHours(-3), WebhookQueuedAtUtc = DateTime.UtcNow },
            new Notice { RequestId = bare.Id, Kind = NoticeKind.Expiring, Step = 7, CreatedAtUtc = DateTime.UtcNow.AddHours(-2), WebhookQueuedAtUtc = DateTime.UtcNow },
            new Notice
            {
                RequestId = Guid.NewGuid(), Kind = NoticeKind.RenewalFailed, Step = 1, Status = NoticeStatus.Resolved,
                CreatedAtUtc = DateTime.UtcNow.AddDays(-2), ResolvedAtUtc = DateTime.UtcNow.AddDays(-1), WebhookQueuedAtUtc = DateTime.UtcNow
            });
        await db.SaveChangesAsync(ct);
        return new Arranged(factory);
    }

    [Fact]
    public async Task Admin_ListsNewestFirst_WithTheNameAndTheMetadataContact()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var page = await admin.GetFromJsonAsync<PagedResult<NoticeItem>>("/v1/notices", ct);

        Assert.Equal(3, page!.TotalCount);
        Assert.Equal(["bare.contoso.local", "contact.contoso.local", null], page.Items.Select(i => i.CommonName));
        var contact = page.Items.Single(i => i.CommonName == "contact.contoso.local");
        Assert.Equal("Platform", contact.OwnerTeam);
        Assert.Equal("ops@contoso.local", contact.ContactEmail);
        var bare = page.Items.Single(i => i.CommonName == "bare.contoso.local");
        Assert.Null(bare.OwnerTeam);
        Assert.Null(bare.ContactEmail);
    }

    [Fact]
    public async Task TheStatusFilter_SelectsOpenOrResolved()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var open = await admin.GetFromJsonAsync<PagedResult<NoticeItem>>("/v1/notices?status=Open", ct);
        var resolved = await admin.GetFromJsonAsync<PagedResult<NoticeItem>>("/v1/notices?status=resolved", ct);

        Assert.Equal(2, open!.TotalCount);
        Assert.All(open.Items, i => Assert.Equal(NoticeStatus.Open, i.Status));
        Assert.Equal(NoticeKind.RenewalFailed, Assert.Single(resolved!.Items).Kind);
    }

    [Fact]
    public async Task TheKindFilter_SelectsOneKind()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var page = await admin.GetFromJsonAsync<PagedResult<NoticeItem>>("/v1/notices?kind=RenewalFailed", ct);

        Assert.Equal(NoticeKind.RenewalFailed, Assert.Single(page!.Items).Kind);
    }

    [Fact]
    public async Task Paging_ReturnsTheRequestedSlice()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var page = await admin.GetFromJsonAsync<PagedResult<NoticeItem>>("/v1/notices?page=2&pageSize=2", ct);

        Assert.Equal(3, page!.TotalCount);
        Assert.Single(page.Items);
        Assert.Equal(2, page.TotalPages);
    }

    [Fact]
    public async Task AHugePageNumber_IsAnEmptyPage_NotAServerError()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.GetAsync("/v1/notices?page=2147483647&pageSize=200", ct);
        var page = await response.Content.ReadFromJsonAsync<PagedResult<NoticeItem>>(ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Empty(page!.Items);
    }

    [Theory]
    [InlineData("status=Bogus")]
    [InlineData("kind=Bogus")]
    public async Task AnUnknownFilterValue_Is400(string query)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.GetAsync($"/v1/notices?{query}", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AViewer_CanList_ButAnotherPermissionCannot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var viewer = arranged.As("viewer");
        using var creator = arranged.As("creator");
        using var anonymous = arranged.Factory.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/v1/notices", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await creator.GetAsync("/v1/notices", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/v1/notices", ct)).StatusCode);
    }

    [Fact]
    public async Task Attention_ShowsTheOpenNotices_ToAViewer_AndWithholdsThemFromAnotherRole()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var viewer = arranged.As("viewer");
        using var creator = arranged.As("creator");

        var seen = await viewer.GetFromJsonAsync<AttentionReport>("/v1/dashboard/attention", ct);
        var withheld = await creator.GetFromJsonAsync<AttentionReport>("/v1/dashboard/attention", ct);

        var item = Assert.Single(seen!.Items, i => i.Kind == AttentionKind.OpenNotices);
        Assert.Equal(2, item.Count);
        Assert.Equal("/notices", item.ActionHref);
        Assert.Equal(["bare.contoso.local", "contact.contoso.local"], item.Evidence.Select(e => e.Label).Order());
        Assert.Contains(AttentionKind.OpenNotices, withheld!.WithheldKinds);
        Assert.DoesNotContain(withheld.Items, i => i.Kind == AttentionKind.OpenNotices);
    }

    [Fact]
    public async Task TheApiClient_ListsWithTheFilters()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);
        var client = new CertificateRequestsApiClient(admin);

        var page = await client.GetNoticesAsync(NoticeStatus.Open, NoticeKind.Expiring, 1, 10, ct);

        Assert.Equal(2, page.TotalCount);
        Assert.All(page.Items, i => Assert.Equal(NoticeKind.Expiring, i.Kind));
    }
}
