using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

/// <summary>
/// The request list pages must ask the server for the page they display. They used to fetch a
/// single page of 100 and filter and count in the browser, so past 100 rows the Pending view — the
/// one approvers work from — silently omitted requests and every chip count was short.
/// </summary>
public sealed class RequestListPagingTests
{
    [Fact]
    public void Pager_OnTheFirstPage_DisablesPrevious()
    {
        using var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();

        var cut = context.Render<Pager>(p => p
            .Add(x => x.Page, 1).Add(x => x.PageSize, 50).Add(x => x.TotalCount, 120));

        Assert.True(cut.Find("[data-test='pager-prev']").HasAttribute("disabled"));
        Assert.False(cut.Find("[data-test='pager-next']").HasAttribute("disabled"));
    }

    [Fact]
    public void Pager_OnTheLastPage_DisablesNext()
    {
        using var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();

        var cut = context.Render<Pager>(p => p
            .Add(x => x.Page, 3).Add(x => x.PageSize, 50).Add(x => x.TotalCount, 120));

        Assert.False(cut.Find("[data-test='pager-prev']").HasAttribute("disabled"));
        Assert.True(cut.Find("[data-test='pager-next']").HasAttribute("disabled"));
    }

    [Fact]
    public void Pager_ShowsTheRangeOfTheCurrentPageAndTheRealTotal()
    {
        using var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();

        var cut = context.Render<Pager>(p => p
            .Add(x => x.Page, 3).Add(x => x.PageSize, 50).Add(x => x.TotalCount, 120));

        Assert.Equal("101–120 of 120", cut.Find("[data-test='pager-range']").TextContent.Trim());
    }

    [Fact]
    public void Pager_ReportsThePageTheUserAskedFor()
    {
        using var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();
        var requested = new List<int>();

        var cut = context.Render<Pager>(p => p
            .Add(x => x.Page, 2).Add(x => x.PageSize, 50).Add(x => x.TotalCount, 120)
            .Add(x => x.OnPageChange, EventCallback.Factory.Create<int>(this, requested.Add)));
        cut.Find("[data-test='pager-next']").Click();
        cut.Find("[data-test='pager-prev']").Click();

        Assert.Equal([3, 1], requested);
    }

    [Fact]
    public void Pager_IsHiddenWhenEverythingFitsOnOnePage()
    {
        using var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();

        var cut = context.Render<Pager>(p => p
            .Add(x => x.Page, 1).Add(x => x.PageSize, 50).Add(x => x.TotalCount, 12));

        Assert.Empty(cut.FindAll("[data-test='pager']"));
    }

    [Fact]
    public void RequestList_AsksTheServerForTheStatusInTheUrl()
    {
        using var host = new Host();
        host.Navigate("http://localhost/certificate-requests?status=Pending");

        var cut = host.Context.Render<CertificateRequests>();
        cut.WaitForElement("#certificate-requests-table");

        Assert.Contains(host.Api.ListQueries, q => q.Contains("status=Pending", StringComparison.Ordinal));
    }

    [Fact]
    public void RequestList_AsksTheServerForThePageInTheUrl()
    {
        using var host = new Host();
        host.Api.TotalCount = 120;
        host.Navigate("http://localhost/certificate-requests?page=3");

        var cut = host.Context.Render<CertificateRequests>();
        cut.WaitForElement("#certificate-requests-table");

        Assert.Contains(host.Api.ListQueries, q => q.Contains("page=3", StringComparison.Ordinal));
    }

    [Fact]
    public void RequestList_ChipCountsComeFromTheCountsEndpointNotTheFetchedPage()
    {
        // One row on the page, 137 Pending in the database: the chip must say 137.
        using var host = new Host();
        host.Api.TotalCount = 137;
        host.Api.Counts = new CertificateRequestStatusCounts
        {
            Total = 137,
            ByStatus = new Dictionary<string, int> { ["Pending"] = 137 }
        };
        host.Navigate("http://localhost/certificate-requests");

        var cut = host.Context.Render<CertificateRequests>();
        cut.WaitForElement("#certificate-requests-table");

        var pendingChip = cut.Find("[data-test='chip-Pending'] .filter-chip-count");
        Assert.Equal("137", pendingChip.TextContent.Trim());
    }

    [Fact]
    public void RequestList_RendersAPagerWhenThereIsMoreThanOnePage()
    {
        using var host = new Host();
        host.Api.TotalCount = 120;
        host.Navigate("http://localhost/certificate-requests");

        var cut = host.Context.Render<CertificateRequests>();
        cut.WaitForElement("#certificate-requests-table");

        Assert.NotEmpty(cut.FindAll("[data-test='pager']"));
    }

    [Theory]
    [InlineData("/v1/certificate-requests/issued", "certificates-table")]
    [InlineData("/v1/certificate-requests/rejected", "denied-requests-table")]
    [InlineData("/v1/certificate-requests/expired", "expired-certificates-table")]
    [InlineData("/v1/certificate-requests/revoked", "revoked-certificates-table")]
    public void SiblingListPages_PageThroughTheServerToo(string listPath, string tableId)
    {
        // These four share the truncation: each loaded a single page and showed whatever fit.
        using var host = new Host();
        host.Api.ListPath = listPath;
        host.Api.TotalCount = 120;
        host.Navigate("http://localhost/?page=2");

        var cut = host.Context.Render(RenderPage(tableId));
        cut.WaitForElement($"#{tableId}");

        Assert.NotEmpty(cut.FindAll("[data-test='pager']"));
        Assert.Contains(host.Api.ListQueries, q => q.Contains("page=2", StringComparison.Ordinal));
    }

    private static RenderFragment RenderPage(string tableId) => tableId switch
    {
        "certificates-table" => builder => { builder.OpenComponent<Certificates>(0); builder.CloseComponent(); },
        "denied-requests-table" => builder => { builder.OpenComponent<DeniedRequests>(0); builder.CloseComponent(); },
        "expired-certificates-table" => builder => { builder.OpenComponent<ExpiredCertificates>(0); builder.CloseComponent(); },
        _ => builder => { builder.OpenComponent<RevokedCertificates>(0); builder.CloseComponent(); },
    };

    [Fact]
    public void CertificatesList_ChipCountsComeFromTheServerNotTheFetchedPage()
    {
        // Same hazard as the request list: these chips are validity buckets, so counting them over
        // one fetched page under-reports every bucket once there are more certificates than fit.
        using var host = new Host();
        host.Api.ListPath = "/v1/certificate-requests/issued";
        host.Api.TotalCount = 300;
        host.Api.ValidityCounts = new IssuedCertificateCounts
        {
            Total = 300,
            ByFilter = new Dictionary<string, int> { ["Valid"] = 240, ["Expiring"] = 60 }
        };
        host.Navigate("http://localhost/certificates");

        var cut = host.Context.Render<Certificates>();
        cut.WaitForElement("#certificates-table");

        Assert.Equal("60", cut.Find("[data-test='chip-Expiring'] .filter-chip-count").TextContent.Trim());
        Assert.Equal("300", cut.Find("[data-test='chip-All'] .filter-chip-count").TextContent.Trim());
    }

    [Fact]
    public void CertificatesList_AsksTheServerForTheValidityFilterInTheUrl()
    {
        using var host = new Host();
        host.Api.ListPath = "/v1/certificate-requests/issued";
        host.Navigate("http://localhost/certificates?filter=Expiring");

        var cut = host.Context.Render<Certificates>();
        cut.WaitForElement("#certificates-table");

        Assert.Contains(host.Api.ListQueries, q => q.Contains("filter=Expiring", StringComparison.Ordinal));
    }

    [Fact]
    public void CertificatesList_ShowsOnlyValidByDefault_AndHidesTheChipsThatWouldBeEmpty()
    {
        using var host = new Host();
        host.Api.ListPath = "/v1/certificate-requests/issued";
        host.Navigate("http://localhost/certificates");

        var cut = host.Context.Render<Certificates>();
        cut.WaitForElement("#certificates-table");

        Assert.True(cut.Find("[data-test='valid-only']").HasAttribute("checked"));
        Assert.Contains("validOnly=true", host.Api.ListQueries.Last(), StringComparison.Ordinal);
        Assert.Contains("validOnly=true", host.Api.CountQueries.Last(), StringComparison.Ordinal);
        Assert.Empty(cut.FindAll("[data-test='chip-Expired']"));
        Assert.Empty(cut.FindAll("[data-test='chip-Revoking']"));
        Assert.Empty(cut.FindAll("[data-test='chip-Revoked']"));
        Assert.NotEmpty(cut.FindAll("[data-test='chip-Expiring']"));
    }

    [Fact]
    public void CertificatesList_UntickingValidOnly_PutsItInTheUrl()
    {
        using var host = new Host();
        host.Api.ListPath = "/v1/certificate-requests/issued";
        host.Navigate("http://localhost/certificates");

        var cut = host.Context.Render<Certificates>();
        cut.WaitForElement("#certificates-table");
        cut.Find("[data-test='valid-only']").Change(false);

        Assert.Contains("valid=0", host.Context.Services.GetRequiredService<NavigationManager>().Uri, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://localhost/certificates?valid=0")]
    [InlineData("http://localhost/certificates?filter=Expired")]   // an old link to an invalid bucket still works
    public void CertificatesList_WithValidOnlyOff_AsksForEverything_AndShowsEveryChip(string url)
    {
        using var host = new Host();
        host.Api.ListPath = "/v1/certificate-requests/issued";
        host.Navigate(url);

        var cut = host.Context.Render<Certificates>();
        cut.WaitForElement("#certificates-table");

        Assert.False(cut.Find("[data-test='valid-only']").HasAttribute("checked"));
        Assert.DoesNotContain("validOnly=true", host.Api.ListQueries.Last(), StringComparison.Ordinal);
        Assert.NotEmpty(cut.FindAll("[data-test='chip-Revoked']"));
    }

    private sealed class Host : IDisposable
    {
        public Host()
        {
            Context.AddAuthorization().SetAuthorized("alice").SetRoles("admin");
            Context.Services.AddSingleton(TimeProvider.System);
            Context.Services.AddAutomationSnippets();
            Context.Services.AddSingleton(new CertificateRequestsApiClient(
                new HttpClient(Api) { BaseAddress = new Uri("http://api.test/") }));
        }

        public BunitContext Context { get; } = new();

        public ListApiStub Api { get; } = new();

        public void Navigate(string uri) =>
            Context.Services.GetRequiredService<NavigationManager>().NavigateTo(uri);

        public void Dispose() => Context.Dispose();
    }

    private sealed class ListApiStub : HttpMessageHandler
    {
        public List<string> ListQueries { get; } = [];

        public List<string> CountQueries { get; } = [];

        public string ListPath { get; set; } = "/v1/certificate-requests";

        public int TotalCount { get; set; } = 1;

        public CertificateRequestStatusCounts Counts { get; set; } = new()
        {
            Total = 1,
            ByStatus = new Dictionary<string, int> { ["Pending"] = 1 }
        };

        public IssuedCertificateCounts ValidityCounts { get; set; } = new()
        {
            Total = 1,
            ByFilter = new Dictionary<string, int> { ["Valid"] = 1 }
        };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;

            if (uri.AbsolutePath == "/v1/certificate-requests/status-counts")
                return Task.FromResult(Json(Counts));

            if (uri.AbsolutePath == "/v1/certificate-requests/issued/validity-counts")
            {
                CountQueries.Add(uri.Query);
                return Task.FromResult(Json(ValidityCounts));
            }

            if (uri.AbsolutePath == ListPath)
            {
                ListQueries.Add(uri.Query);
                return Task.FromResult(Json(new PagedResult<CertificateRequest>
                {
                    Items =
                    [
                        new CertificateRequest
                        {
                            CommonName = "api.contoso.local",
                            RequestedBy = "alice@contoso.local",
                            Status = CertificateRequestStatus.Pending,
                            CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                            UpdatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                        }
                    ],
                    TotalCount = TotalCount,
                    Page = 1,
                    PageSize = 50
                }));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(value, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
        };
    }
}
