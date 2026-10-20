using System.Net;
using System.Net.Http.Json;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class CertificateInventoryCliTests
{
    [Fact]
    public async Task Export_CollectsEveryPageAsCertificateItems()
    {
        var ct = TestContext.Current.CancellationToken;
        var id = (CertificateRequestId)Guid.NewGuid();
        var seen = new List<string>();
        using var http = new HttpClient(new PageHandler(request =>
        {
            seen.Add(request.RequestUri!.Query);
            var page = seen.Count;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new PagedResult<CertificateInventoryItem>
                {
                    Page = page, PageSize = 1, TotalCount = 2,
                    Items = [new CertificateInventoryItem { RequestId = id, Leg = page == 1 ? "primary" : "pqc" }]
                })
            };
        })) { BaseAddress = new Uri("https://api.example/") };

        var items = await CertificateInventoryExport.CollectAsync(new CertificateRequestsApiClient(http), 1, ct);

        Assert.Equal(["primary", "pqc"], items.Select(i => i.Leg));
        Assert.Equal(["?page=1&pageSize=1", "?page=2&pageSize=1"], seen);
        var json = System.Text.Json.JsonSerializer.Serialize(items, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        Assert.Contains("\"requestId\"", json);
        Assert.DoesNotContain("CertificatePem", json);
    }

    private sealed class PageHandler(Func<HttpRequestMessage, HttpResponseMessage> reply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(reply(request));
    }
}
