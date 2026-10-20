using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// The policy editor shows and edits key custody, and says plainly what requiring a
/// client-generated key costs: only ACME and EST enrollment can satisfy it.
/// </summary>
public sealed class PolicyDetailKeyCustodyTests
{
    private static readonly Guid PolicyId = Guid.Parse("5a5a5a5a-0000-0000-0000-000000000002");

    private static BunitContext Context(KeyCustodyMode published)
    {
        var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new PolicyStub(published)) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    [Fact]
    public async Task PublishedCustody_IsShown_AndTheDraftEditorOffersTheChoice()
    {
        await using var context = Context(KeyCustodyMode.RequireClientGenerated);

        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));

        cut.WaitForAssertion(() => Assert.Contains("Key custody", cut.Markup));
        Assert.Contains("Client-generated key required", cut.Markup);
        var select = cut.Find("#key-custody");
        Assert.Equal(nameof(KeyCustodyMode.RequireClientGenerated), select.GetAttribute("value"));
    }

    [Fact]
    public async Task Editor_SaysWhichEnrollmentRoutesCanSatisfyTheRule()
    {
        await using var context = Context(KeyCustodyMode.Any);

        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));

        cut.WaitForAssertion(() => Assert.NotNull(cut.Find("#key-custody")));
        // The consequence is not obvious from the setting's name, so the page states it.
        Assert.Contains("ACME", cut.Markup);
        Assert.Contains("EST", cut.Markup);
    }

    [Fact]
    public async Task UnrestrictedCustody_IsShownAsTheCaGeneratingTheKey()
    {
        await using var context = Context(KeyCustodyMode.Any);

        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));

        cut.WaitForAssertion(() => Assert.Contains("CA may generate the key", cut.Markup));
    }

    private sealed class PolicyStub(KeyCustodyMode published) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            object body = request.RequestUri!.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal)
                ? Array.Empty<IssuancePolicyVersionResponse>()
                : new IssuancePolicyResponse
                {
                    Id = new IssuancePolicyId(PolicyId),
                    Name = "corp",
                    Published = new IssuancePolicyVersionResponse
                    {
                        Id = Guid.NewGuid(), VersionNumber = 1, Status = IssuancePolicyVersionStatus.Published,
                        KeyCustody = published
                    }
                };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
            });
        }
    }
}
