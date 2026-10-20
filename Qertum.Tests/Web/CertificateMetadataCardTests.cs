using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Shared;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Web;

public sealed class CertificateMetadataCardTests
{
    private sealed class Api(Func<HttpResponseMessage> answer) : HttpMessageHandler
    {
        public string? LastBody { get; private set; }
        public int Puts { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Put)
            {
                Puts++;
                LastBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            }
            return answer();
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body, string? correlationId = null)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (correlationId is not null) response.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
        return response;
    }

    private static IRenderedComponent<CertificateMetadataCard> Render(Api api, CertificateMetadata? metadata = null)
    {
        var context = new BunitContext();
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        var request = new CertificateRequest
        {
            CommonName = "meta.contoso.local", RequestedBy = "alice", Metadata = metadata ?? new()
        };
        return context.Render<CertificateMetadataCard>(p => p.Add(c => c.Certificate, request));
    }

    private static string Text(IRenderedComponent<CertificateMetadataCard> cut, string id) =>
        cut.Find($"[data-test='metadata-{id}']").TextContent.Trim();

    [Fact]
    public void ShowsEveryRecordedFact_AndUnknownForTheOthers()
    {
        var cut = Render(new Api(() => Json(HttpStatusCode.OK, "{}")), new CertificateMetadata { OwnerTeam = "Platform" });

        Assert.Equal("Platform", Text(cut, "owner-team"));
        Assert.Equal("Unknown", Text(cut, "purpose"));
        Assert.Equal("Unknown", Text(cut, "compatibility-note"));
    }

    [Fact]
    public void EditIsClosedByDefault_AndOpensAPrefilledForm()
    {
        var cut = Render(new Api(() => Json(HttpStatusCode.OK, "{}")), new CertificateMetadata { OwnerTeam = "Platform" });
        Assert.Empty(cut.FindAll("input"));

        cut.Find("[data-test='metadata-edit']").Click();

        Assert.Equal(6, cut.FindAll("input").Count);
        Assert.Equal("Platform", cut.Find("input[data-test='metadata-input-owner-team']").GetAttribute("value"));
    }

    [Fact]
    public async Task Save_SendsTheWholeSet_AndShowsWhatTheServerStored()
    {
        var api = new Api(() => Json(HttpStatusCode.OK, """{"ownerTeam":"Platform","ticketReference":"OPS-9"}"""));
        var cut = Render(api, new CertificateMetadata { OwnerTeam = "Old" });
        cut.Find("[data-test='metadata-edit']").Click();
        cut.Find("input[data-test='metadata-input-owner-team']").Change("Platform");
        cut.Find("input[data-test='metadata-input-ticket-reference']").Change("OPS-9");

        await cut.Find("[data-test='metadata-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Equal("OPS-9", Text(cut, "ticket-reference")));
        using var sent = JsonDocument.Parse(api.LastBody!);
        Assert.Equal("Platform", sent.RootElement.GetProperty("ownerTeam").GetString());
        Assert.Equal("OPS-9", sent.RootElement.GetProperty("ticketReference").GetString());
        Assert.Empty(cut.FindAll("input"));
    }

    [Fact]
    public async Task Save_Refused_ExplainsWhoMayEdit_AndKeepsTheForm()
    {
        var cut = Render(new Api(() => new HttpResponseMessage(HttpStatusCode.Forbidden)));
        cut.Find("[data-test='metadata-edit']").Click();

        await cut.Find("[data-test='metadata-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Contains("certificates.manage", Text(cut, "error")));
        Assert.Equal(6, cut.FindAll("input").Count);
    }

    [Fact]
    public async Task Save_Rejected_ShowsTheProblemWithItsCorrelationId()
    {
        var cut = Render(new Api(() => Json(HttpStatusCode.BadRequest,
            """{"title":"One or more validation errors occurred.","detail":"OwnerTeam is too long."}""", "abc123def456")));
        cut.Find("[data-test='metadata-edit']").Click();

        await cut.Find("[data-test='metadata-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Contains("(correlation id: abc123def456)", Text(cut, "error")));
    }

    [Fact]
    public void TheCardCarriesNoInlineStyle()
    {
        var cut = Render(new Api(() => Json(HttpStatusCode.OK, "{}")));
        cut.Find("[data-test='metadata-edit']").Click();

        Assert.DoesNotContain("style=", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }
}
