using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.Text.Json;
using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// "Renewed From" links to another request on the same route template, so the router keeps the page
/// instance and only sets a new <c>Id</c>. Loading once per instance left the renewal on screen and
/// made the link look dead; the page must reload whenever the id changes.
/// </summary>
public sealed class CertificateRequestDetailNavigationTests
{
    [Fact]
    public async Task ChangingId_OnTheSameInstance_LoadsTheNewRequest()
    {
        var source = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = "source.contoso.com",
            Type = "WebServer",
            Status = CertificateRequestStatus.Revoked,
            RevocationReason = "keyCompromise"
        };
        var renewal = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = "renewal.contoso.com",
            Type = "WebServer",
            Status = CertificateRequestStatus.Pending,
            RenewedFromId = source.Id
        };

        await using var context = new BunitContext();

        context.Services.AddSingleton(TimeProvider.System);

        context.Services.AddAutomationSnippets();
        context.AddAuthorization().SetAuthorized("alice");
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new RequestStub(source, renewal)) { BaseAddress = new Uri("http://api.test/") }));

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)renewal.Id));
        cut.WaitForAssertion(() => Assert.Contains("renewal.contoso.com", cut.Find("h1").TextContent));

        cut.Render(p => p.Add(x => x.Id, (Guid)source.Id));

        cut.WaitForAssertion(() => Assert.Contains("source.contoso.com", cut.Find("h1").TextContent));
        Assert.Contains("keyCompromise", cut.Markup);
        Assert.DoesNotContain("Renewed From", cut.Markup);
    }

    private sealed class RequestStub(params CertificateRequest[] requests) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var match = requests.FirstOrDefault(r =>
                request.Method == HttpMethod.Get &&
                request.RequestUri!.AbsolutePath == $"/v1/certificate-requests/{r.Id}");

            return Task.FromResult(match is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(match, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
                });
        }
    }
}
