using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

public sealed class EnrollmentWizardPqcStageTests
{
    private static IRenderedComponent<NewCertificateRequest> RenderAtKey(WizardTestHost host, string purpose = "WebServer")
    {
        var cut = host.Context.Render<NewCertificateRequest>();
        cut.WaitForElement("[data-step='Purpose']");
        cut.Find($"[data-purpose='{purpose}']").Click();
        cut.WaitForElement("[data-step='Names']");
        cut.Find("#common-name").Change("api.contoso.com");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Key']");
        return cut;
    }

    [Theory]
    [InlineData(PqcStage.Enforce)]
    [InlineData(PqcStage.Pilot)]
    public async Task WhereNewClassicalIsRefused_ClassicalChoicesAndThePilotToggleAreNotRendered(PqcStage stage)
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: stage);

        var cut = RenderAtKey(host);

        Assert.Empty(cut.FindAll("#pilot-pqc"));
        Assert.Empty(cut.FindAll("[data-algorithm='RSA']"));
        Assert.Empty(cut.FindAll("[data-algorithm='ECDSA-P256']"));
        Assert.Equal("true", cut.Find("[data-algorithm='ML-DSA-65']").GetAttribute("aria-pressed"));
        Assert.NotEmpty(cut.FindAll("[data-test='pqc-stage-refused']"));
    }

    [Fact]
    public async Task AtPilot_TheNoteSaysRenewalsAreStillAllowed()
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: PqcStage.Pilot);

        var cut = RenderAtKey(host);

        Assert.Contains("renewals", cut.Find("[data-test='pqc-stage-refused']").TextContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AtWarn_ClassicalIsOfferedWithAWarningCallout()
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: PqcStage.Warn);

        var cut = RenderAtKey(host);

        Assert.NotEmpty(cut.FindAll("[data-algorithm='ECDSA-P256']"));
        Assert.Equal(PqcStageGuidance.Sentence(PqcStage.Warn), cut.Find("[data-test='pqc-stage-warning']").TextContent.Trim());
    }

    [Theory]
    [InlineData(PqcStage.Off)]
    [InlineData(PqcStage.Observe)]
    public async Task AtOffAndObserve_NothingIsShown(PqcStage stage)
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: stage);

        var cut = RenderAtKey(host);

        Assert.Empty(cut.FindAll("[data-test='pqc-stage-warning']"));
        Assert.Empty(cut.FindAll("[data-test='pqc-stage-refused']"));
        Assert.NotEmpty(cut.FindAll("[data-algorithm='ECDSA-P256']"));
    }

    [Fact]
    public async Task TemplatesWithDifferentStages_ChangeWhatIsOffered()
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: PqcStage.Enforce, otherStage: PqcStage.Off);

        var web = RenderAtKey(host, "WebServer");
        Assert.Empty(web.FindAll("[data-algorithm='ECDSA-P256']"));

        await using var host2 = new WizardTestHost();
        host2.Api.Options = WizardApiStub.DefaultOptions(webServerStage: PqcStage.Enforce, otherStage: PqcStage.Off);
        var client = host2.Context.Render<NewCertificateRequest>();
        client.WaitForElement("[data-step='Purpose']");
        client.Find("[data-purpose='ClientAuthentication']").Click();
        client.WaitForElement("[data-template='ClientAuth']").Click();
        client.WaitForElement("[data-step='Names']");
        client.Find("#common-name").Change("device-1");
        client.Find("[data-action='next']").Click();
        client.WaitForElement("[data-step='Key']");
        Assert.NotEmpty(client.FindAll("[data-algorithm='ECDSA-P256']"));
    }

    [Fact]
    public async Task ReturnedWarnings_AreShownBeforeLeavingTheWizard()
    {
        await using var host = new WizardTestHost();
        host.Api.Options = WizardApiStub.DefaultOptions(webServerStage: PqcStage.Warn);
        host.Api.SubmitResponseJson = """{"warnings":["'ECDSA-P256' is moving to post-quantum."]}""";
        var cut = RenderAtKey(host);
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Review']");

        cut.Find("#submit-request").Click();

        cut.WaitForElement("[data-test='submit-warnings']");
        Assert.Contains("moving to post-quantum", cut.Find("[data-test='submit-warnings']").TextContent);
        Assert.DoesNotContain("/certificate-requests", host.Context.Services
            .GetRequiredService<Microsoft.AspNetCore.Components.NavigationManager>().Uri);
        cut.Find("[data-test='continue-after-warnings']").Click();
        Assert.EndsWith("/certificate-requests", host.Context.Services
            .GetRequiredService<Microsoft.AspNetCore.Components.NavigationManager>().Uri);
    }
}
