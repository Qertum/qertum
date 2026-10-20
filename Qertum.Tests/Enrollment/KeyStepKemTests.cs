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
/// ML-KEM is offered wherever post-quantum algorithms are, under its own heading because a KEM key
/// encrypts rather than signs — except for a template that issues a CA certificate, whose key must
/// sign. The server refuses that combination anyway (<c>PolicyRules.KeyCapability</c>); the form
/// just never offers it, and the review step sends the requester back to the key step if it happens.
/// </summary>
public sealed class KeyStepKemTests
{
    private static readonly string[] KemValues = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

    [Fact]
    public void TheThreeSetsAreKemChoicesWhoseNoteSaysTheyEncrypt()
    {
        var kem = AlgorithmChoices.All.Where(c => c.Kind == AlgorithmKind.Kem).ToList();

        Assert.Equal(KemValues, kem.Select(c => c.Value));
        Assert.All(kem, c => Assert.Contains("encrypt", c.Note, StringComparison.Ordinal));
        Assert.All(kem, c => Assert.Contains("cannot sign", c.Note, StringComparison.Ordinal));
    }

    [Fact]
    public void KemIsHiddenUntilPostQuantumIsPilotedAndShownWhenClassicalIsRefused()
    {
        Assert.DoesNotContain(AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: false), c => c.Kind == AlgorithmKind.Kem);
        Assert.Equal(3, AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: true).Count(c => c.Kind == AlgorithmKind.Kem));
        Assert.Equal(3, AlgorithmChoices.Visible(classicalRefused: true, pilotPqc: false).Count(c => c.Kind == AlgorithmKind.Kem));
    }

    [Fact]
    public async Task KemChoicesAreGroupedUnderTheirOwnHeading()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, DraftFor(EnrollmentPurpose.Email)));

        Assert.Equal(KemValues, KemCards(cut).Select(c => c.GetAttribute("data-algorithm")));
        Assert.Contains("encryption", cut.Find("[data-test='kem-choices'] .form-label").TextContent, StringComparison.Ordinal);
        // Listed once, under that heading, and not again among the signature algorithms.
        Assert.Equal(3, cut.FindAll("[data-algorithm^='ML-KEM']").Count);
    }

    [Fact]
    public async Task ChoosingKemShowsItsScopeNoteAndTheKemPathNote()
    {
        await using var context = new BunitContext();
        var draft = DraftFor(EnrollmentPurpose.Email);
        draft.KeyAlgorithm = "ML-KEM-768";
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, draft).Add(x => x.CaAlgorithm, "RSA"));

        Assert.Equal(CertificateAlgorithmSummary.KemScopeNote, cut.Find("[data-test='kem-scope-note']").TextContent.Trim());
        Assert.Contains("ML-KEM key", cut.Find("[data-test='enrollment-path-note']").TextContent, StringComparison.Ordinal);
        Assert.Empty(cut.FindAll("[data-test='composite-scope-note']"));
    }

    [Fact]
    public async Task ASubordinateCaTemplateOffersNoKemChoice()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, DraftFor(EnrollmentPurpose.SubordinateCa)));

        Assert.NotEmpty(cut.FindAll("[data-algorithm='ML-DSA-65']"));
        Assert.Empty(KemCards(cut));
        Assert.Empty(cut.FindAll("[data-test='kem-choices']"));
    }

    [Fact]
    public async Task AKeyCapabilityRefusalOnReviewLinksBackToTheKeyStep()
    {
        await using var context = new BunitContext();
        var cut = context.Render<ReviewStep>(p => p
            .Add(x => x.Draft, DraftFor(EnrollmentPurpose.SubordinateCa))
            .Add(x => x.SubmitError, "Refused by issuance policy.")
            .Add(x => x.Violations, [new IssuancePolicyViolation(PolicyRules.KeyCapability, "ML-KEM-768", "cannot be a CA key")]));

        Assert.Equal(nameof(WizardStep.Key), cut.Find("[data-edit-step]").GetAttribute("data-edit-step"));
    }

    [Fact]
    public async Task OnboardingNeverOffersMlKemForTheRoot()
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
        Assert.DoesNotContain(offered, v => v!.StartsWith("ML-KEM", StringComparison.Ordinal));
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

    private static IReadOnlyList<AngleSharp.Dom.IElement> KemCards(IRenderedComponent<KeyStep> cut) =>
        [.. cut.FindAll("[data-test='kem-choices'] [data-algorithm]")];

    // The CA status call fails, which onboarding treats as "not configured yet".
    private sealed class NotFoundHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
