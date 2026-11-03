using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// A refused publish says why beside the Publish button. The reason used to go to the notification at the
/// top of the page, out of view from the buttons at the bottom, so the button looked like it did nothing.
/// </summary>
public sealed class PolicyDetailPublishTests
{
    private static readonly Guid PolicyId = Guid.Parse("5a5a5a5a-0000-0000-0000-000000000003");
    private const string Refusal = "Maximum validity of 30 days is below the default validity of linked templates: WebServer (365 days).";

    [Fact]
    public async Task RefusedPublish_ShowsTheReasonBesideTheButtons()
    {
        var stub = new PolicyStub(HttpStatusCode.UnprocessableEntity, "Issuance Policy Invariant Violation", Refusal);
        await using var context = Context(stub);
        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));
        cut.WaitForAssertion(() => Assert.Contains("Publish", cut.Markup));

        cut.FindAll("button").Single(b => b.TextContent.Trim() == "Publish").Click();

        cut.WaitForAssertion(() => Assert.Contains(Refusal, cut.Find("[data-test='draft-error']").TextContent));
        Assert.Contains("correlation id: 0af7651916cd43dd8448eb211c80319c", cut.Find("[data-test='draft-error']").TextContent);
        Assert.Empty(cut.FindAll("[data-test='notification']"));
        Assert.Empty(cut.FindAll("[data-test='lifecycle-error']"));
    }

    [Fact]
    public async Task RefusedArchive_ShowsTheReasonInTheLifecycleSection()
    {
        var stub = new PolicyStub(HttpStatusCode.Conflict, "Issuance Policy Conflict", "Issuance policy 'corp' is linked to a template. Unlink it before archiving.");
        await using var context = Context(stub);
        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));
        cut.WaitForAssertion(() => Assert.Contains("Archive", cut.Markup));

        cut.FindAll("button").Single(b => b.TextContent.Trim() == "Archive").Click();

        cut.WaitForAssertion(() => Assert.Contains("Unlink it before archiving", cut.Find("[data-test='lifecycle-error']").TextContent));
        Assert.Empty(cut.FindAll("[data-test='draft-error']"));
    }

    private static BunitContext Context(PolicyStub stub)
    {
        var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(_ => new CertificateRequestsApiClient(
            new HttpClient(stub) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    /// <summary>Serves a policy with a draft; every POST is refused with the given problem.</summary>
    private sealed class PolicyStub(HttpStatusCode refusal, string title, string detail) : HttpMessageHandler
    {
        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                var problem = new HttpResponseMessage(refusal)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new { title, detail }), Encoding.UTF8, "application/problem+json")
                };
                problem.Headers.Add("X-Correlation-Id", "0af7651916cd43dd8448eb211c80319c");
                return problem;
            }

            object body = request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? Array.Empty<IssuancePolicyVersionResponse>()
                : new IssuancePolicyResponse
                {
                    Id = new IssuancePolicyId(PolicyId),
                    Name = "corp",
                    Draft = new IssuancePolicyVersionResponse
                    {
                        Id = Guid.NewGuid(), VersionNumber = 2, Status = IssuancePolicyVersionStatus.Draft,
                        MaxValidityDays = 30
                    }
                };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
            };
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(Send(request, cancellationToken));
    }
}
