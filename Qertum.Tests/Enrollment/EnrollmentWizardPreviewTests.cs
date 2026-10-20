using Bunit;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The preview runs against the real HTTP client, so these tests observe the token HttpClient hands
/// the handler: cancelling on new input, on step change and on dispose must abort the actual call,
/// and a superseded call that completes late must never overwrite the current verdict.
/// </summary>
public sealed class EnrollmentWizardPreviewTests
{
    private static readonly TimeSpan Debounce = NewCertificateRequest.PreviewDebounce;

    private static IRenderedComponent<NewCertificateRequest> RenderAtNames(WizardTestHost host)
    {
        var cut = host.Context.Render<NewCertificateRequest>();
        cut.WaitForElement("[data-purpose='WebServer']").Click();
        cut.WaitForElement("[data-step='Names']");
        return cut;
    }

    private static PendingPreview StartPreview(WizardTestHost host, IRenderedComponent<NewCertificateRequest> cut,
        string commonName, int expectedCount)
    {
        cut.Find("#common-name").Change(commonName);
        host.Time.Advance(Debounce);
        cut.WaitForAssertion(() => Assert.Equal(expectedCount, host.Api.Previews.Count));
        return host.Api.Previews[expectedCount - 1];
    }

    [Fact]
    public async Task RapidInput_InsideTheDebounceWindow_SendsOneRequest()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);

        cut.Find("#common-name").Change("a.contoso.com");
        host.Time.Advance(Debounce / 4);
        cut.Find("#common-name").Change("ab.contoso.com");
        host.Time.Advance(Debounce / 4);

        Assert.Empty(host.Api.Previews);

        host.Time.Advance(Debounce);

        cut.WaitForAssertion(() => Assert.Single(host.Api.Previews));
        Assert.Equal("ab.contoso.com", host.Api.Previews[0].Request.CommonName);
    }

    [Fact]
    public async Task NewInput_CancelsTheInFlightRequest()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);
        var first = StartPreview(host, cut, "one.contoso.com", expectedCount: 1);

        cut.Find("#common-name").Change("two.contoso.com");

        cut.WaitForAssertion(() => Assert.True(first.Token.IsCancellationRequested));
        host.Time.Advance(Debounce);
        cut.WaitForAssertion(() => Assert.Equal(2, host.Api.Previews.Count));
        Assert.False(host.Api.Previews[1].Token.IsCancellationRequested);
        Assert.Equal("two.contoso.com", host.Api.Previews[1].Request.CommonName);
    }

    [Fact]
    public async Task StepChange_CancelsTheInFlightRequest()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);
        var inFlight = StartPreview(host, cut, "one.contoso.com", expectedCount: 1);

        cut.Find("[data-action='back']").Click();

        cut.WaitForElement("[data-step='Purpose']");
        cut.WaitForAssertion(() => Assert.True(inFlight.Token.IsCancellationRequested));
    }

    [Fact]
    public async Task Dispose_CancelsTheInFlightRequest()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);
        var inFlight = StartPreview(host, cut, "one.contoso.com", expectedCount: 1);

        await host.Context.DisposeComponentsAsync();

        Assert.True(inFlight.Token.IsCancellationRequested);
    }

    [Fact]
    public async Task SupersededResult_ReleasedLate_DoesNotReplaceTheCurrentVerdict()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);
        var stale = StartPreview(host, cut, "one.contoso.com", expectedCount: 1);
        var current = StartPreview(host, cut, "two.contoso.com", expectedCount: 2);

        current.Allow();
        cut.WaitForElement("[data-preview='allowed']");

        stale.Reject("stale verdict");
        await stale.Response.Task;
        // Two dispatcher round-trips so the stale continuation has run before asserting its absence.
        await cut.InvokeAsync(() => { });
        await cut.InvokeAsync(() => { });

        Assert.Empty(cut.FindAll("[data-preview='rejected']"));
        Assert.DoesNotContain("stale verdict", cut.Markup);
        Assert.NotNull(cut.Find("[data-preview='allowed']"));
    }

    [Fact]
    public async Task Submit_StaysEnabled_WhileAPreviewIsInFlight()
    {
        await using var host = new WizardTestHost();
        var cut = RenderAtNames(host);
        cut.Find("#common-name").Change("api.contoso.com");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Key']");
        cut.Find("[data-action='next']").Click();
        cut.WaitForElement("[data-step='Review']");

        host.Time.Advance(Debounce);
        cut.WaitForAssertion(() => Assert.Contains(host.Api.Previews, p => !p.Token.IsCancellationRequested));

        cut.WaitForElement("[data-preview='checking']");
        Assert.False(cut.Find("#submit-request").HasAttribute("disabled"));
    }
}
