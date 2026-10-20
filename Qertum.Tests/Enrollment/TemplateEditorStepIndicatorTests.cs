using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The template editor's step indicator uses the shared <c>.wizard-steps</c> classes rather than
/// inline styles, so it cannot drift away from the enrollment wizard's.
/// </summary>
public sealed class TemplateEditorStepIndicatorTests
{
    private static BunitContext Host()
    {
        var context = new BunitContext();
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.AddAuthorization().SetAuthorized("alice").SetRoles("admin")
            .SetPolicies(AppPermissions.SettingsEdit);
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new TemplateEditorApiStub()) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    [Fact]
    public void UsesTheSharedWizardStepMarkup()
    {
        using var context = Host();

        var cut = context.Render<TemplateEditor>();

        var steps = cut.WaitForElement("ol.wizard-steps");
        Assert.Equal(4, cut.FindAll("ol.wizard-steps > li").Count);
        Assert.NotNull(steps);
    }

    [Fact]
    public void CarriesNoInlineStylingOnTheIndicator()
    {
        // The whole point of the port: an inline-styled copy drifts from the shared one silently.
        using var context = Host();

        var cut = context.Render<TemplateEditor>();
        cut.WaitForElement("ol.wizard-steps");

        Assert.All(cut.FindAll("ol.wizard-steps li"),
            li => Assert.False(li.HasAttribute("style")));
    }

    [Fact]
    public void MarksTheFirstStepCurrentAndNoneDone()
    {
        using var context = Host();

        var cut = context.Render<TemplateEditor>();
        cut.WaitForElement("ol.wizard-steps");

        var items = cut.FindAll("ol.wizard-steps > li");
        Assert.Contains("current", items[0].ClassList);
        Assert.All(items, li => Assert.DoesNotContain("done", li.ClassList));
    }

    [Fact]
    public void TheCurrentStepIsNotALink()
    {
        using var context = Host();

        var cut = context.Render<TemplateEditor>();
        cut.WaitForElement("ol.wizard-steps");

        var current = cut.Find("ol.wizard-steps > li.current");
        Assert.Empty(current.QuerySelectorAll("button"));
    }

    [Fact]
    public void AStepTwoAheadIsNeverALink()
    {
        // GoToStep allows only a completed step or the immediately next one once it validates;
        // the markup must not offer anything the guard would refuse.
        using var context = Host();

        var cut = context.Render<TemplateEditor>();
        cut.WaitForElement("ol.wizard-steps");

        Assert.DoesNotContain("3", cut.FindAll("[data-goto-step]").Select(b => b.GetAttribute("data-goto-step")));
        Assert.DoesNotContain("4", cut.FindAll("[data-goto-step]").Select(b => b.GetAttribute("data-goto-step")));
    }

    private sealed class TemplateEditorApiStub : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
