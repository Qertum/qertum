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
    public async Task ShowsOnlyValidCasByDefault_AndUntickingAsksForAll()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Issuers.Add(IssuerApiStub.Issuer("Root"));

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-test='issuer-row']")));
        Assert.True(cut.Find("[data-test='valid-only']").HasAttribute("checked"));
        Assert.Contains("/v1/issuers?validOnly=true", api.Queries);

        cut.Find("[data-test='valid-only']").Change(false);

        cut.WaitForAssertion(() => Assert.Contains("/v1/issuers", api.Queries));
        Assert.False(cut.Find("[data-test='valid-only']").HasAttribute("checked"));
    }

    [Fact]
    public async Task RenewIsOfferedForActiveAndRevokedIntermediates_NotForRoots()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var root = IssuerApiStub.Issuer("Root");
        api.Issuers.AddRange([
            root,
            IssuerApiStub.Issuer("Active", kind: IssuerKind.Intermediate, parent: root.Id),
            IssuerApiStub.Issuer("Revoked", status: IssuerStatus.Retired, kind: IssuerKind.Intermediate, parent: root.Id) with { RevokedAtUtc = DateTime.UtcNow },
            IssuerApiStub.Issuer("Retired", status: IssuerStatus.Retired, kind: IssuerKind.Intermediate, parent: root.Id)]);

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Equal(4, cut.FindAll("[data-test='issuer-row']").Count));
        Assert.Equal(2, cut.FindAll("[data-test='action-renew']").Count);
    }

    [Fact]
    public async Task ValidZeroInTheUrl_ShowsEveryIssuer()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Issuers.Add(IssuerApiStub.Issuer("Root"));
        context.Services.GetRequiredService<Microsoft.AspNetCore.Components.NavigationManager>().NavigateTo("http://localhost/issuers?valid=0");

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Single(cut.FindAll("[data-test='issuer-row']")));
        Assert.False(cut.Find("[data-test='valid-only']").HasAttribute("checked"));
        Assert.Contains("/v1/issuers", api.Queries);
        Assert.DoesNotContain("/v1/issuers?validOnly=true", api.Queries);
    }

    [Fact]
    public async Task AnImmediateRenewal_SaysSoWithTheNewExpiry()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var intermediate = IssuerApiStub.Issuer("Issuing", kind: IssuerKind.Intermediate);
        api.Issuers.Add(intermediate);
        var replacement = intermediate with { Id = new IssuerId(Guid.NewGuid()), RenewalOfIssuerId = intermediate.Id };
        api.Override = request => request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/renew")
            ? Json(new CreateIntermediateResponse(replacement, null)) : null;

        var cut = context.Render<IssuersPage>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-renew']")));
        cut.Find("[data-test='action-renew']").Click();
        cut.Find("[data-test='confirm-panel'] .btn-danger").Click();

        cut.WaitForAssertion(() => Assert.Contains("Renewed", cut.Find("[data-test='notification']").TextContent));
        Assert.Contains(replacement.ValidTo!.Value.ToString("yyyy-MM-dd"), cut.Find("[data-test='notification']").TextContent);
    }

    [Fact]
    public async Task RenewIsNotOfferedOnceAReplacementExists()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var old = IssuerApiStub.Issuer("Issuing", status: IssuerStatus.Retired, kind: IssuerKind.Intermediate) with { RevokedAtUtc = DateTime.UtcNow };
        api.Issuers.AddRange([old, IssuerApiStub.Issuer("Issuing", kind: IssuerKind.Intermediate) with { RenewalOfIssuerId = old.Id }]);

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='issuer-row']").Count));
        Assert.Single(cut.FindAll("[data-test='action-renew']")); // only on the replacement
    }

    [Fact]
    public async Task Renew_AsksFirst_ThenPostsAndReloads()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var intermediate = IssuerApiStub.Issuer("Issuing", kind: IssuerKind.Intermediate);
        api.Issuers.Add(intermediate);
        api.Override = request => request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/renew")
            ? Json(new CreateIntermediateResponse(intermediate, null)) : null;

        var cut = context.Render<IssuersPage>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-renew']")));
        cut.Find("[data-test='action-renew']").Click();

        Assert.Contains("new key", cut.Find("[data-test='confirm-panel']").TextContent);
        Assert.DoesNotContain(api.Requests, r => r.Path.EndsWith("/renew"));
        cut.Find("[data-test='confirm-panel'] .btn-danger, [data-test='confirm-panel'] .btn-primary").Click();
        cut.WaitForAssertion(() => Assert.Contains(api.Requests, r => r.Method == HttpMethod.Post && r.Path == $"/v1/issuers/{intermediate.Id}/renew"));
    }

    [Fact]
    public async Task ARoundTripRenewal_OpensTheCeremonyOnThePendingReplacement()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var intermediate = IssuerApiStub.Issuer("Issuing", kind: IssuerKind.Intermediate);
        var replacement = IssuerApiStub.Issuer("Issuing", status: IssuerStatus.PendingCertificate, kind: IssuerKind.Intermediate) with { RenewalOfIssuerId = intermediate.Id };
        api.Issuers.Add(intermediate);
        var file = new IntermediateRequestFile(IntermediateRequestFile.CurrentFormat, replacement.Id, "Issuing", "csr", 365, 0, [], [], [], []);
        api.Override = request =>
        {
            if (request.Method == HttpMethod.Post && request.RequestUri!.AbsolutePath.EndsWith("/renew"))
            {
                api.Issuers.Add(replacement);
                return Json(new CreateIntermediateResponse(replacement, file));
            }
            return request.RequestUri!.AbsolutePath.EndsWith("/request") ? Json(file) : null;
        };

        var cut = context.Render<IssuersPage>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='action-renew']")));
        cut.Find("[data-test='action-renew']").Click();
        cut.Find("[data-test='confirm-panel'] .btn-danger, [data-test='confirm-panel'] .btn-primary").Click();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='issuer-ceremony']")));
    }

    [Fact]
    public async Task APendingReplacement_SaysItIsARenewal()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Issuers.Add(IssuerApiStub.Issuer("Issuing", status: IssuerStatus.PendingCertificate, kind: IssuerKind.Intermediate)
            with { RenewalOfIssuerId = new IssuerId(Guid.NewGuid()) });

        var cut = context.Render<IssuersPage>();

        cut.WaitForAssertion(() => Assert.Contains("Renewal of Issuing", cut.Find("[data-test='renewal-of']").TextContent));
    }

    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            System.Text.Encoding.UTF8, "application/json")
    };

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
