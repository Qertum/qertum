using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Layout;

namespace Qertum.Tests.Web;

/// <summary>
/// The sidebar's Pending item carries the exact number of requests awaiting approval, read from
/// <c>/status-counts</c> rather than from a page-capped list. A count that could not be read must
/// not look like "nothing pending".
/// </summary>
public sealed class PendingRequestsBadgeTests : IDisposable
{
    private readonly BunitContext context = new();
    private readonly CountsStub api = new();

    public PendingRequestsBadgeTests()
    {
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
    }

    public void Dispose() => context.Dispose();

    [Fact]
    public void ShowsThePendingCount()
    {
        api.Pending = 142;

        var cut = context.Render<PendingRequestsBadge>();

        cut.WaitForAssertion(() =>
            Assert.Equal("142", cut.Find("[data-test='pending-badge']").TextContent.Trim()));
        Assert.Equal("/v1/certificate-requests/status-counts", api.Requests.Single().AbsolutePath);
        Assert.Equal("", api.Requests.Single().Query.TrimStart('?'));
    }

    [Fact]
    public void RendersNothingWhenNothingIsPending()
    {
        api.Pending = 0;

        var cut = context.Render<PendingRequestsBadge>();

        cut.WaitForAssertion(() => Assert.Single(api.Requests));
        Assert.Empty(cut.FindAll("[data-test='pending-badge']"));
        Assert.Empty(cut.FindAll("[data-test='pending-badge-unavailable']"));
    }

    [Fact]
    public void AFailedReadIsShownAsUnavailableNotAsZero()
    {
        api.Fail = true;

        var cut = context.Render<PendingRequestsBadge>();

        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-test='pending-badge-unavailable']")));
        Assert.Empty(cut.FindAll("[data-test='pending-badge']"));
    }

    [Fact]
    public void ReReadsTheCountOnNavigation()
    {
        api.Pending = 3;
        var cut = context.Render<PendingRequestsBadge>();
        cut.WaitForAssertion(() => Assert.Equal("3", cut.Find("[data-test='pending-badge']").TextContent.Trim()));

        api.Pending = 2;
        context.Services.GetRequiredService<NavigationManager>().NavigateTo("certificate-requests/some-id");

        cut.WaitForAssertion(() => Assert.Equal("2", cut.Find("[data-test='pending-badge']").TextContent.Trim()));
        Assert.Equal(2, api.Requests.Count);
    }

    private sealed class CountsStub : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        public int Pending { get; set; }

        public bool Fail { get; set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            lock (Requests)
                Requests.Add(request.RequestUri!);

            if (Fail)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));

            var counts = new CertificateRequestStatusCounts
            {
                Total = Pending + 7,
                ByStatus = new Dictionary<string, int> { ["Pending"] = Pending, ["Issued"] = 7 }
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(counts), Encoding.UTF8, "application/json")
            });
        }
    }
}
