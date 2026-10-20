using Bunit;
using Microsoft.AspNetCore.Components;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

public sealed class EnrollmentWizardFlowTests
{
    private static IRenderedComponent<NewCertificateRequest> RenderAtPurpose(WizardTestHost host)
    {
        var cut = host.Context.Render<NewCertificateRequest>();
        cut.WaitForElement("[data-step='Purpose']");
        return cut;
    }

    private static IRenderedComponent<NewCertificateRequest> RenderAtNames(WizardTestHost host)
    {
        var cut = RenderAtPurpose(host);
        cut.Find("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Names']");
        return cut;
    }

    private static IRenderedComponent<NewCertificateRequest> RenderAtKey(WizardTestHost host)
    {
        var cut = RenderAtNames(host);
        cut.Find("#common-name").Change("api.contoso.com");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Key']");
        return cut;
    }

    [Fact]
    public async Task OptionsLoadFailure_ShowsUnavailableWithRetry()
    {
        await using var host = new WizardTestHost();
        host.Api.FailOptions = true;

        var cut = host.Context.Render<NewCertificateRequest>();

        cut.WaitForElement("[data-state='options-unavailable']");
        Assert.Empty(cut.FindAll("[data-purpose]"));

        host.Api.FailOptions = false;
        cut.Find("#retry-options").Click();
        cut.WaitForElement("[data-purpose='WebServer']");
    }

    [Fact]
    public async Task SingleTemplatePurpose_GoesStraightToNames_WithTemplateSanFields()
    {
        await using var host = new WizardTestHost();

        var cut = RenderAtNames(host);

        Assert.NotNull(cut.Find("#dns-names"));
        Assert.NotNull(cut.Find("#ip-addrs"));
        Assert.Empty(cut.FindAll("#emails"));
    }

    [Fact]
    public async Task MultiTemplatePurpose_ExpandsTemplateChoice()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtPurpose(host);

        cut.Find("[data-purpose='ClientAuthentication']").Click();

        Assert.NotNull(cut.Find("[data-step='Purpose']"));
        Assert.Equal(2, cut.FindAll("[data-template]").Count);

        cut.Find("[data-template='DeviceAuth']").Click();
        cut.WaitForElement("[data-step='Names']");
        Assert.NotNull(cut.Find("#dns-names"));
    }

    [Fact]
    public async Task ChooseTemplateDirectly_ListsEveryTemplate()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtPurpose(host);

        cut.Find("[data-purpose='direct']").Click();

        Assert.Equal(3, cut.FindAll("[data-template]").Count);
    }

    [Fact]
    public async Task KeyStep_RecommendsEcdsaForWebServer_AndOffersPqcOnlyWhenPiloted()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtKey(host);

        Assert.Equal("true", cut.Find("[data-algorithm='ECDSA-P256']").GetAttribute("aria-pressed"));
        Assert.Empty(cut.FindAll("[data-algorithm='ML-DSA-65']"));

        cut.Find("#pilot-pqc").Change(true);
        cut.Find("[data-algorithm='ML-DSA-65']").Click();
        Assert.Equal("true", cut.Find("[data-algorithm='ML-DSA-65']").GetAttribute("aria-pressed"));

        cut.Find("#pilot-pqc").Change(false);
        Assert.Empty(cut.FindAll("[data-algorithm='ML-DSA-65']"));
        Assert.Equal("true", cut.Find("[data-algorithm='ECDSA-P256']").GetAttribute("aria-pressed"));
    }

    [Fact]
    public async Task Back_KeepsEnteredNames()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtKey(host);

        cut.Find("[data-action='back']").Click();

        cut.WaitForElement("[data-step='Names']");
        Assert.Equal("api.contoso.com", cut.Find("#common-name").GetAttribute("value"));
    }

    [Fact]
    public async Task Submit_PostsTheBuiltRequestAndNavigatesToRequests()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);

        cut.Find("#common-name").Change("api.contoso.com");
        cut.Find("#dns-names").Change("www.contoso.com");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Key']");
        cut.Find("[data-algorithm='ECDSA-P384']").Click();
        cut.Find("#validity-days").Change("30");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Review']");

        cut.Find("#submit-request").Click();

        cut.WaitForAssertion(() => Assert.Single(host.Api.Submitted));
        var submitted = host.Api.Submitted[0];
        Assert.Equal("api.contoso.com", submitted.CommonName);
        Assert.Equal("WebServer", submitted.Type);
        Assert.Equal(CertificateKeyAlgorithm.EcdsaP384, submitted.KeyAlgorithm);
        Assert.Equal(30, submitted.ValidityDays);
        Assert.Contains("www.contoso.com", submitted.PropertiesJson);
        cut.WaitForAssertion(() => Assert.EndsWith("/certificate-requests",
            host.Context.Services.GetRequiredService<NavigationManager>().Uri));
    }

    private static void UseRoutes(WizardTestHost host, string? acmeTemplate, string? estTemplate,
        bool eabRequired = false, bool acmeAutoApprove = false)
    {
        var defaults = WizardApiStub.DefaultOptions();
        host.Api.Options = new EnrollmentOptionsResponse
        {
            Purposes = defaults.Purposes,
            Templates = defaults.Templates,
            Acme = acmeTemplate is null ? null : new AcmeEnrollmentRoute
            {
                TemplateTypeKey = acmeTemplate,
                DirectoryUrl = "https://acme.contoso.test/acme/directory",
                ExternalAccountBindingRequired = eabRequired,
                AutoApprove = acmeAutoApprove
            },
            Est = estTemplate is null ? null : new EstEnrollmentRoute
            {
                TemplateTypeKey = estTemplate,
                BaseUrl = "https://est.contoso.test/.well-known/est"
            }
        };
    }

    [Fact]
    public async Task RouteStep_IsSkipped_WhenNoProtocolNamesTheTemplate()
    {
        await using var host = new WizardTestHost();
        UseRoutes(host, acmeTemplate: "ClientAuth", estTemplate: null);

        RenderAtNames(host);
    }

    [Fact]
    public async Task RouteStep_OffersWebAcmeAndEst_WhenBothNameTheTemplate()
    {
        await using var host = new WizardTestHost();
        UseRoutes(host, acmeTemplate: "WebServer", estTemplate: "WebServer");
        var cut = RenderAtPurpose(host);

        cut.Find("[data-purpose='WebServer']").Click();

        cut.WaitForElement("[data-step='Route']");
        Assert.NotNull(cut.Find("[data-route='web']"));
        Assert.NotNull(cut.Find("[data-route='acme']"));
        Assert.NotNull(cut.Find("[data-route='est']"));
    }

    [Fact]
    public async Task ChoosingAcme_ShowsProtocolFactsAndFilesNothing()
    {
        await using var host = new WizardTestHost();
        UseRoutes(host, acmeTemplate: "WebServer", estTemplate: null, eabRequired: true, acmeAutoApprove: false);
        var cut = RenderAtPurpose(host);
        cut.Find("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Route']");

        cut.Find("[data-route='acme']").Click();

        cut.WaitForElement("[data-step='Protocol']");
        Assert.Equal("https://acme.contoso.test/acme/directory", cut.Find("[data-protocol-url]").TextContent.Trim());
        Assert.Contains("external account binding", cut.Markup);
        Assert.Contains("waits for an approver", cut.Markup);
        Assert.Empty(host.Api.Submitted);
        Assert.Empty(host.Api.Previews);
    }

    [Fact]
    public async Task ChoosingWeb_ContinuesToNames_AndBackReturnsToRoute()
    {
        await using var host = new WizardTestHost();
        UseRoutes(host, acmeTemplate: null, estTemplate: "WebServer");
        var cut = RenderAtPurpose(host);
        cut.Find("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Route']");

        cut.Find("[data-route='web']").Click();
        cut.WaitForElement("[data-step='Names']");
        cut.Find("[data-action='back']").Click();

        cut.WaitForElement("[data-step='Route']");
    }

    [Fact]
    public async Task ChooseTemplateDirectly_SkipsTheRouteStep()
    {
        await using var host = new WizardTestHost();
        UseRoutes(host, acmeTemplate: "WebServer", estTemplate: "WebServer");
        var cut = RenderAtPurpose(host);

        cut.Find("[data-purpose='direct']").Click();
        cut.Find("[data-template='WebServer']").Click();

        cut.WaitForElement("[data-step='Names']");
    }
}
