using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class AcmeOrderPagesTests
{
    private static readonly Guid OrderId = Guid.NewGuid();

    [Fact]
    public async Task TheList_ShowsEachOrdersNamesStatusAndLastFailure()
    {
        await using var context = NewContext(new PagedResult<AcmeOrderSummary>
        {
            Items = [Summary()], TotalCount = 1, Page = 1, PageSize = 50
        }, detail: null);

        var cut = context.Render<AcmeOrders>();

        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-test='acme-order-row']")));
        var row = cut.Find("[data-test='acme-order-row']").TextContent;
        Assert.Contains("stuck.example.com", row);
        Assert.Contains("DnsNoTxtRecord", cut.Find("[data-test='acme-order-failure']").TextContent);
    }

    [Fact]
    public async Task TheDetail_ShowsAuthorizationsAndHistoryWithHints()
    {
        await using var context = NewContext(list: null, detail: new AcmeOrderDetail
        {
            Order = Summary(),
            Authorizations =
            [
                new() { Identifier = "stuck.example.com", Status = "pending", Challenges = [new() { Type = "dns-01", Status = "processing", Attempts = 2 }] }
            ],
            History =
            [
                new() { OccurredAtUtc = DateTime.UtcNow, Kind = TimelineEntryKind.Diagnostic, Action = "ChallengeAttemptFailed",
                        Category = "DnsNoTxtRecord", Detail = "No TXT record.", Hint = "Publish the TXT record." }
            ]
        });

        var cut = context.Render<AcmeOrderView>(p => p.Add(x => x.Id, OrderId));

        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-test='acme-authorization']")));
        Assert.Contains("dns-01", cut.Find("[data-test='acme-authorization']").TextContent);
        Assert.Equal("Publish the TXT record.", cut.Find("[data-test='diagnostic-hint']").TextContent.Trim());
    }

    [Fact]
    public async Task AFailedLoad_SaysUnavailable()
    {
        await using var context = NewContext(list: null, detail: null);

        var cut = context.Render<AcmeOrders>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='acme-orders-unavailable']")));
    }

    private static AcmeOrderSummary Summary() => new()
    {
        Id = OrderId, AccountId = Guid.NewGuid(), Identifiers = ["stuck.example.com"], Status = "pending",
        CreatedAtUtc = DateTime.UtcNow, ExpiresAtUtc = DateTime.UtcNow.AddDays(7),
        LastFailureCategory = "DnsNoTxtRecord", LastFailureDetail = "No TXT record.", LastFailureAtUtc = DateTime.UtcNow
    };

    private static BunitContext NewContext(PagedResult<AcmeOrderSummary>? list, AcmeOrderDetail? detail)
    {
        var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit);
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new Stub(list, detail)) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private sealed class Stub(PagedResult<AcmeOrderSummary>? list, AcmeOrderDetail? detail) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            object? body = request.RequestUri!.AbsolutePath == "/v1/acme/orders/" || request.RequestUri.AbsolutePath == "/v1/acme/orders"
                ? list
                : detail;
            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
                });
        }
    }
}
