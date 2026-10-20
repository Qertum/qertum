using Qertum.Tests.Web;
using System.Net;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Services.Policies;
using Qertum.Web.Components.Pages;
using Qertum.Web.Components.Pages.Enrollment;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The signing + encryption pairs are offered wherever post-quantum algorithms are, under their own heading,
/// and never for a template that issues a CA certificate (the server refuses that combination as well).
/// </summary>
public sealed class KeyStepPairTests
{
    private static readonly string[] PairValues =
        ["PAIR-ML-DSA-44-ML-KEM-512", "PAIR-ML-DSA-65-ML-KEM-768", "PAIR-ML-DSA-87-ML-KEM-1024"];

    [Fact]
    public void TheThreeLevels_ArePairChoicesWhoseNoteSaysTwoCertificatesAndNotComposite()
    {
        var pairs = AlgorithmChoices.All.Where(c => c.Kind == AlgorithmKind.Pair).ToList();

        Assert.Equal(PairValues, pairs.Select(c => c.Value));
        Assert.All(pairs, c => Assert.Contains("two separate certificates", c.Note, StringComparison.Ordinal));
        Assert.All(pairs, c => Assert.Contains("not a composite", c.Note, StringComparison.Ordinal));
        Assert.All(pairs, c => Assert.Contains("cannot sign", c.Note, StringComparison.Ordinal));
    }

    [Fact]
    public void PairsAreHiddenUntilPostQuantumIsPilotedAndShownWhenClassicalIsRefused()
    {
        Assert.DoesNotContain(AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: false), c => c.Kind == AlgorithmKind.Pair);
        Assert.Equal(3, AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: true).Count(c => c.Kind == AlgorithmKind.Pair));
        Assert.Equal(3, AlgorithmChoices.Visible(classicalRefused: true, pilotPqc: false).Count(c => c.Kind == AlgorithmKind.Pair));
    }

    [Fact]
    public async Task PairChoicesAreGroupedUnderTheirOwnHeading_AndListedOnce()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, DraftFor(EnrollmentPurpose.Email)));

        Assert.Equal(PairValues, cut.FindAll("[data-test='pair-choices'] [data-algorithm]").Select(c => c.GetAttribute("data-algorithm")));
        Assert.Contains("signing", cut.Find("[data-test='pair-choices'] .form-label").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, cut.FindAll("[data-algorithm^='PAIR-']").Count);
    }

    [Fact]
    public async Task ChoosingAPairShowsItsOwnScopeNote_NotTheHybridOne()
    {
        await using var context = new BunitContext();
        var draft = DraftFor(EnrollmentPurpose.Email);
        draft.KeyAlgorithm = "PAIR-ML-DSA-65-ML-KEM-768";
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, draft).Add(x => x.CaAlgorithm, "RSA"));

        Assert.Equal(CertificateAlgorithmSummary.PairScopeNote, cut.Find("[data-test='pair-scope-note']").TextContent.Trim());
        Assert.Empty(cut.FindAll("[data-test='paired-scope-note']"));
        Assert.Empty(cut.FindAll("[data-test='kem-scope-note']"));
    }

    [Fact]
    public async Task ASubordinateCaTemplateOffersNoPairChoice()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, DraftFor(EnrollmentPurpose.SubordinateCa)));

        Assert.NotEmpty(cut.FindAll("[data-algorithm='ML-DSA-65']"));
        Assert.Empty(cut.FindAll("[data-algorithm^='PAIR-']"));
        Assert.Empty(cut.FindAll("[data-test='pair-choices']"));
    }

    [Fact]
    public async Task OnboardingNeverOffersAPairForTheRoot()
    {
        await using var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit);
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddAutomationSnippets();
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new NotFoundHandler()) { BaseAddress = new Uri("http://api.test/") }));
        var cut = context.Render<Onboarding>();
        cut.FindAll("button.option-card").Single(b => b.TextContent.Contains("Generate new CA", StringComparison.Ordinal)).Click();

        var offered = cut.FindAll("#gen-algo option").Select(o => o.GetAttribute("value")).ToList();

        Assert.NotEmpty(offered);
        Assert.DoesNotContain(offered, v => v!.StartsWith("PAIR-", StringComparison.Ordinal));
    }

    private static EnrollmentDraft DraftFor(EnrollmentPurpose purpose)
    {
        var draft = new EnrollmentDraft();
        draft.SelectTemplate(
            new EnrollmentTemplateSummary { TypeKey = purpose.ToString(), Name = purpose.ToString(), DefaultValidityDays = 365, Purposes = [purpose] },
            purpose, classicalRefused: false);
        // Selecting a template turns the pilot off; the requester turns it back on.
        draft.PilotPqc = true;
        return draft;
    }

    // The CA status call fails, which onboarding treats as "not configured yet".
    private sealed class NotFoundHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
