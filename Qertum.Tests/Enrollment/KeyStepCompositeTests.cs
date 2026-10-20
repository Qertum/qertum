using Bunit;
using Qertum.Web.Components.Pages;
using Qertum.Web.Components.Pages.Enrollment;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// Eighteen composite combinations would bury the key step, so two are shown and the rest wait
/// behind "show all", grouped by their classical half. Every combination stays reachable, and a
/// chosen one is never hidden by the collapse.
/// </summary>
public sealed class KeyStepCompositeTests
{
    [Fact]
    public void EveryCompositeCombinationIsAChoiceWithAReadableLabel()
    {
        var composite = AlgorithmChoices.All.Where(c => c.Kind == AlgorithmKind.Composite).ToList();

        Assert.Equal(18, composite.Count);
        Assert.Equal(["MLDSA65-ECDSA-P256-SHA512", "MLDSA87-ECDSA-P384-SHA512"], composite.Where(c => c.Featured).Select(c => c.Value));
        Assert.Equal("ML-DSA-65 + ECDSA P-256", composite.Single(c => c.Value == "MLDSA65-ECDSA-P256-SHA512").Label);
        Assert.Equal("ML-DSA-65 + ECDSA brainpoolP256r1", composite.Single(c => c.Value == "MLDSA65-ECDSA-brainpoolP256r1-SHA512").Label);
        Assert.Equal("ML-DSA-44 + RSA-2048 PKCS#1 v1.5", composite.Single(c => c.Value == "MLDSA44-RSA2048-PKCS15-SHA256").Label);
        Assert.Equal("ML-DSA-87 + Ed448", composite.Single(c => c.Value == "MLDSA87-Ed448-SHAKE256").Label);
        Assert.All(composite, c => Assert.Equal(AlgorithmChoices.CompositeNote, c.Note));
        Assert.All(composite, c => Assert.Contains(c.Group!, AlgorithmChoices.CompositeGroups));
    }

    [Fact]
    public void CompositeIsHiddenUntilPostQuantumIsPilotedAndShownWhenClassicalIsRefused()
    {
        Assert.DoesNotContain(AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: false), c => c.Kind == AlgorithmKind.Composite);
        Assert.Equal(18, AlgorithmChoices.Visible(classicalRefused: false, pilotPqc: true).Count(c => c.Kind == AlgorithmKind.Composite));
        Assert.Equal(18, AlgorithmChoices.Visible(classicalRefused: true, pilotPqc: false).Count(c => c.Kind == AlgorithmKind.Composite));
    }

    [Fact]
    public async Task OnlyTheFeaturedPairIsShownUntilShowAllIsClicked()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft, new EnrollmentDraft { KeyAlgorithm = "ECDSA-P256", PilotPqc = true }));

        Assert.Equal(2, CompositeCards(cut).Count);

        cut.Find("[data-action='show-all-composite']").Click();

        Assert.Equal(18, CompositeCards(cut).Count);
        Assert.Equal(
            AlgorithmChoices.CompositeGroups,
            cut.FindAll("[data-composite-group]").Select(g => g.GetAttribute("data-composite-group")!));
    }

    [Fact]
    public async Task AChosenNonFeaturedCombinationStaysVisible()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p.Add(x => x.Draft,
            new EnrollmentDraft { KeyAlgorithm = "MLDSA87-Ed448-SHAKE256", PilotPqc = true }));

        Assert.Single(cut.FindAll("[data-algorithm='MLDSA87-Ed448-SHAKE256'][aria-pressed='true']"));
        Assert.Empty(cut.FindAll("[data-action='show-all-composite']"));
    }

    [Fact]
    public async Task ChoosingCompositeShowsItsScopeNoteAndThePathNote()
    {
        await using var context = new BunitContext();
        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, new EnrollmentDraft { KeyAlgorithm = "MLDSA65-ECDSA-P256-SHA512", PilotPqc = true })
            .Add(x => x.CaAlgorithm, "RSA"));

        Assert.Equal(CertificateAlgorithmSummary.CompositeScopeNote, cut.Find("[data-test='composite-scope-note']").TextContent.Trim());
        Assert.Contains("not fully post-quantum", cut.Find("[data-test='enrollment-path-note']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-test='paired-scope-note']"));
    }

    private static IReadOnlyList<AngleSharp.Dom.IElement> CompositeCards(IRenderedComponent<KeyStep> cut) =>
        [.. cut.FindAll("[data-test='composite-choices'] [data-algorithm]")];
}
