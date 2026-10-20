using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>The policy editor shows and edits the requester-role rule like the other rule lists.</summary>
public sealed class PolicyDetailRequesterRolesTests
{
    private static readonly Guid PolicyId = Guid.Parse("5a5a5a5a-0000-0000-0000-000000000001");

    [Fact]
    public async Task PublishedRoles_AreShown_AndTheDraftEditorOffersARoleList()
    {
        await using var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new PolicyStub()) { BaseAddress = new Uri("http://api.test/") }));

        var cut = context.Render<PolicyDetail>(p => p.Add(x => x.PolicyId, PolicyId));

        cut.WaitForAssertion(() => Assert.Contains("Requester roles", cut.Markup));
        Assert.Contains("ops, pki", cut.Markup);
        Assert.NotNull(cut.Find("#role-entry"));
    }

    private sealed class PolicyStub : HttpMessageHandler
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
                        AllowedRequesterRoles = ["ops", "pki"]
                    }
                };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
            });
        }
    }
}
