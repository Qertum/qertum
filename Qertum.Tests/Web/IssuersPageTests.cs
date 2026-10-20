using System.Net;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using IssuersPage = Qertum.Web.Components.Pages.Issuers;

namespace Qertum.Tests.Web;

public sealed class IssuersPageTests
{
    private static (BunitContext Context, IssuerApiStub Api) NewContext()
    {
        var api = new IssuerApiStub();
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.AddAuthorization().SetAuthorized("admin").SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    [Fact]
    public async Task RendersTheTree_WithStatusCustodyAndDefaultBadges()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var root = IssuerApiStub.Issuer("Offline Root", custody: IssuerKeyCustody.Offline);
        api.Issuers.AddRange([root, IssuerApiStub.Issuer("Issuing", isDefault: true, kind: IssuerKind.Intermediate, parent: root.Id)]);

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='issuer-row']").Count));
        Assert.Single(cut.FindAll("[data-test='badge-default']"));
        Assert.Contains(cut.FindAll("[data-test='badge-custody']"), b => b.TextContent.Contains("Offline"));
        Assert.Contains("corp.example", cut.Markup);
        Assert.Contains("issuer-depth-1", cut.FindAll("[data-test='issuer-row']")[1].InnerHtml);
    }

    [Fact]
    public async Task PendingIssuer_OffersResumeAndDelete_ButNotMakeDefault()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Issuers.Add(IssuerApiStub.Issuer("Pending", status: IssuerStatus.PendingCertificate, kind: IssuerKind.Intermediate));

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-resume']")));
        Assert.NotEmpty(cut.FindAll("[data-test='action-delete']"));
        Assert.Empty(cut.FindAll("[data-test='action-make-default']"));
    }

    [Fact]
    public async Task Retire_AsksForConfirmation_BeforeCallingTheApi()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var old = IssuerApiStub.Issuer("Old");
        api.Issuers.AddRange([IssuerApiStub.Issuer("Current", isDefault: true), old]);
        var cut = context.Render<IssuersPage>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-retire']")));

        cut.Find("[data-test='action-retire']").Click();
        Assert.DoesNotContain(api.Requests, r => r.Method == HttpMethod.Post);
        cut.Find("[data-test='confirm-panel'] button.btn-danger").Click();

        cut.WaitForAssertion(() => Assert.Contains(api.Requests, r => r.Method == HttpMethod.Post && r.Path == $"/v1/issuers/{old.Id}/retire"));
    }

    [Fact]
    public async Task ApiRefusal_IsShownVerbatim()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Issuers.AddRange([IssuerApiStub.Issuer("Current", isDefault: true), IssuerApiStub.Issuer("Old", status: IssuerStatus.Retired)]);
        api.Override = r => r.Method == HttpMethod.Post
            ? IssuerApiStub.Problem(HttpStatusCode.Conflict, "'Old' still has 3 unexpired certificate(s)")
            : null;
        var cut = context.Render<IssuersPage>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-archive']")));

        cut.Find("[data-test='action-archive']").Click();
        cut.Find("[data-test='confirm-panel'] button.btn-danger").Click();

        cut.WaitForAssertion(() => Assert.Contains("3 unexpired", cut.Find("[data-test='issuer-error']").TextContent));
    }

    [Fact]
    public async Task Ceremony_OfflinePath_ShowsTheSignCommandsAfterCreate()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var pending = IssuerApiStub.Issuer("New Issuing", status: IssuerStatus.PendingCertificate, kind: IssuerKind.Intermediate);
        api.Override = r => r.Method == HttpMethod.Post && r.RequestUri!.AbsolutePath == "/v1/issuers/intermediates"
            ? new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(JsonSerializer.Serialize(new CreateIntermediateResponse(pending,
                    new IntermediateRequestFile(IntermediateRequestFile.CurrentFormat, pending.Id, pending.Name,
                        "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n", 1825, 0, ["corp.example"], [], [], [])),
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)), System.Text.Encoding.UTF8, "application/json")
            }
            : null;
        var cut = context.Render<IssuersPage>();

        cut.Find("[data-test='create-intermediate']").Click();
        cut.Find("#ceremony-name").Change("New Issuing");
        cut.Find("#ceremony-cn").Change("New Issuing");
        cut.Find("#ceremony-parent").Change("");
        cut.Find("[data-test='ceremony-submit']").Click();

        cut.WaitForAssertion(() => Assert.Contains("qca root sign", cut.Find("[data-test='ceremony-sign-step']").TextContent));
        var sent = api.Requests.Single(r => r.Path == "/v1/issuers/intermediates").Body!;
        Assert.Contains("\"parentIssuerId\":null", sent);
        Assert.Contains("\"keyAlgorithm\":\"ECDSA-P384\"", sent);
    }

    [Fact]
    public async Task Ceremony_AlgorithmList_ExcludesHybridAndKem()
    {
        var (context, _) = NewContext();
        await using var __ = context;
        var cut = context.Render<IssuersPage>();

        cut.Find("[data-test='create-intermediate']").Click();
        var offered = cut.FindAll("#ceremony-algorithm option").Select(o => o.GetAttribute("value")).ToHashSet();

        Assert.Contains("ECDSA-P384", offered);
        Assert.Contains("ML-DSA-65", offered);
        Assert.DoesNotContain("HYBRID-ECDSA-P256", offered);
        Assert.DoesNotContain("ML-KEM-768", offered);
    }
}
