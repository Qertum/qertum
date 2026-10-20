using System.Net;
using System.Text;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class NoticesPageTests
{
    private sealed class Api(Func<HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls.Add(request.RequestUri!.PathAndQuery);
            return Task.FromResult(answer());
        }
    }

    private const string OneNotice = """
        {"items":[{"id":"11111111-1111-1111-1111-111111111111","requestId":"22222222-2222-2222-2222-222222222222","kind":"RenewalStalled","step":2,"status":"Open","commonName":"a.contoso.local","createdAtUtc":"2026-10-14T09:00:00Z","ownerTeam":"Platform","contactEmail":"ops@contoso.local"}],"totalCount":1,"page":1,"pageSize":50}
        """;

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK, string? correlationId = null)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (correlationId is not null) response.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
        return response;
    }

    private static (IRenderedComponent<Notices> Cut, Api Handler) Render(Func<HttpResponseMessage> answer)
    {
        var handler = new Api(answer);
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://api.test/") }));
        return (context.Render<Notices>(), handler);
    }

    [Fact]
    public void ShowsTheOpenNoticesByDefault_WithTheContact()
    {
        var (cut, handler) = Render(() => Json(OneNotice));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='notice-row']")));
        Assert.Contains("status=Open", Assert.Single(handler.Calls));
        var row = cut.Find("[data-test='notice-row']").TextContent;
        Assert.Contains("a.contoso.local", row);
        Assert.Contains("renewal waiting for approval (level 2)", row);
        Assert.Contains("Platform", row);
        Assert.Contains("ops@contoso.local", row);
    }

    [Fact]
    public void ANoticeWithNoRecordedContact_ReadsUnknown()
    {
        var (cut, _) = Render(() => Json(OneNotice.Replace("\"ownerTeam\":\"Platform\",\"contactEmail\":\"ops@contoso.local\"", "\"ownerTeam\":null")));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='notice-row']")));
        Assert.Contains("Unknown", cut.Find("[data-test='notice-contact']").TextContent);
    }

    [Fact]
    public void WithNoNotices_ShowsAnEmptyState()
    {
        var (cut, _) = Render(() => Json("""{"items":[],"totalCount":0,"page":1,"pageSize":50}"""));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='notices-empty']")));
    }

    [Fact]
    public void AFailedLoad_ShowsTheProblemWithItsCorrelationId()
    {
        var (cut, _) = Render(() => Json("""{"title":"Server error","detail":"database unavailable"}""", HttpStatusCode.InternalServerError, "abc123def456"));

        cut.WaitForAssertion(() => Assert.Contains("(correlation id: abc123def456)", cut.Find("[data-test='notices-error']").TextContent));
    }

    [Fact]
    public void TheFilterChips_NavigateWithTheStatusInTheQueryString()
    {
        var (cut, _) = Render(() => Json(OneNotice));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='notice-row']")));

        cut.Find("[data-test='chip-Resolved']").Click();

        Assert.Contains("status=Resolved", cut.Services.GetRequiredService<Microsoft.AspNetCore.Components.NavigationManager>().Uri);
    }

    [Fact]
    public void ThePageCarriesNoInlineStyle()
    {
        var (cut, _) = Render(() => Json(OneNotice));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='notice-row']")));

        Assert.DoesNotContain("style=", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }
}
