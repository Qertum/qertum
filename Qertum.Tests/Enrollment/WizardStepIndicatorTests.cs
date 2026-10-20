using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The enrollment wizard's step indicator. Finished steps are navigable, matching the template
/// editor's indicator; steps ahead are not, because moving forward carries side effects (selecting
/// a template, choosing a protocol) that only each step's own action performs.
/// </summary>
public sealed class WizardStepIndicatorTests
{
    private static IRenderedComponent<NewCertificateRequest> RenderAtKey(WizardTestHost host)
    {
        var cut = host.Context.Render<NewCertificateRequest>();
        cut.WaitForElement("[data-step='Purpose']");
        cut.Find("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Names']");
        cut.Find("#common-name").Change("api.contoso.com");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Key']");
        return cut;
    }

    [Fact]
    public async Task FinishedStepsAreNavigable()
    {
        await using var host = new WizardTestHost();

        var cut = RenderAtKey(host);

        Assert.Equal(["Purpose", "Names"],
            cut.FindAll("[data-goto-step]").Select(b => b.GetAttribute("data-goto-step")));
    }

    [Fact]
    public async Task TheCurrentStepIsNotNavigable()
    {
        await using var host = new WizardTestHost();

        var cut = RenderAtKey(host);

        Assert.DoesNotContain("Key", cut.FindAll("[data-goto-step]").Select(b => b.GetAttribute("data-goto-step")));
    }

    [Fact]
    public async Task StepsAheadAreNotNavigable()
    {
        // Advancing runs the step's own action — selecting a template, choosing a protocol. Letting
        // the indicator jump forward would skip that and leave a half-built draft.
        await using var host = new WizardTestHost();

        var cut = RenderAtKey(host);

        Assert.DoesNotContain("Review", cut.FindAll("[data-goto-step]").Select(b => b.GetAttribute("data-goto-step")));
    }

    [Fact]
    public async Task ClickingAFinishedStepGoesBackToIt()
    {
        await using var host = new WizardTestHost();

        var cut = RenderAtKey(host);
        cut.Find("[data-goto-step='Names']").Click();

        cut.WaitForElement("[data-step='Names']");
    }

    [Fact]
    public async Task GoingBackKeepsWhatWasAlreadyEntered()
    {
        // One draft lives for the page, so stepping back must not blank the fields.
        await using var host = new WizardTestHost();

        var cut = RenderAtKey(host);
        cut.Find("[data-goto-step='Names']").Click();
        cut.WaitForElement("[data-step='Names']");

        Assert.Equal("api.contoso.com", cut.Find("#common-name").GetAttribute("value"));
    }

    [Fact]
    public async Task FromTheProtocolStep_TheEarlierStepIsStillNavigable()
    {
        // Protocol is displayed under the Route entry, so the indicator must still resolve
        // "finished" correctly rather than treating Protocol as a step of its own.
        await using var host = new WizardTestHost();
        host.Api.Options = new EnrollmentOptionsResponse
        {
            Purposes = WizardApiStub.DefaultOptions().Purposes,
            Templates = WizardApiStub.DefaultOptions().Templates,
            Acme = new AcmeEnrollmentRoute
            {
                TemplateTypeKey = "WebServer",
                DirectoryUrl = "https://acme.contoso.local/acme/directory",
                AutoApprove = true
            }
        };
        var cut = host.Context.Render<NewCertificateRequest>();
        cut.WaitForElement("[data-step='Purpose']");
        cut.Find("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Route']");
        cut.Find("[data-route='acme']").Click();
        cut.WaitForElement("[data-step='Protocol']");

        cut.Find("[data-goto-step='Purpose']").Click();

        cut.WaitForElement("[data-step='Purpose']");
    }
}
