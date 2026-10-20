using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class PqcStageSettingsTests
{
    private static IRenderedComponent<Settings> RenderIssuance(BunitContext context)
    {
        var cut = context.Render<Settings>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-issuance")));
        cut.Find("#settings-tab-issuance").Click();
        return cut;
    }

    private static IReadOnlyList<(HttpMethod Method, string Path, string? Body)> Requests(BunitContext context) =>
        context.Services.GetRequiredService<SettingsPageHarness.RequestLog>().Requests.ToList();

    [Fact]
    public void EveryStageHasADistinctSentence()
    {
        var sentences = Enum.GetValues<PqcStage>().Select(PqcStageGuidance.Sentence).ToList();

        Assert.Equal(sentences.Count, sentences.Distinct().Count());
        Assert.All(sentences, s => Assert.False(string.IsNullOrWhiteSpace(s)));
        Assert.Contains("renewals", PqcStageGuidance.Sentence(PqcStage.Pilot), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("no grace period", PqcStageGuidance.Sentence(PqcStage.Enforce), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(PqcStage.Off, false, false)]
    [InlineData(PqcStage.Observe, false, false)]
    [InlineData(PqcStage.Warn, false, true)]
    [InlineData(PqcStage.Pilot, true, true)]
    [InlineData(PqcStage.Enforce, true, false)]
    public void StageHelpers_MatchTheStageTable(PqcStage stage, bool refusesNew, bool warns)
    {
        Assert.Equal(refusesNew, PqcStageGuidance.RefusesNewClassical(stage));
        Assert.Equal(warns, PqcStageGuidance.WarnsRequester(stage));
    }

    [Fact]
    public async Task Settings_ShowsAStageSelectWithOneSentencePerStage()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Warn");
        var cut = RenderIssuance(context);

        var options = cut.FindAll("#pqc-stage option").Select(o => o.GetAttribute("value")).ToArray();
        Assert.Equal(Enum.GetNames<PqcStage>(), options);
        Assert.Equal(PqcStageGuidance.Sentence(PqcStage.Warn), cut.Find("[data-test='pqc-stage-help']").TextContent.Trim());
    }

    [Fact]
    public async Task Settings_KeepsThePqcOnlyScopeNote()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true);
        var cut = RenderIssuance(context);

        Assert.Equal(AlgorithmPolicyGuidance.PqcOnlyScope, cut.Find("[data-test='pqc-only-scope']").TextContent.Trim());
        Assert.Contains(AlgorithmPolicyGuidance.PqcOnlyAllowedAlgorithms, cut.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Settings_LooseningTheStage_AsksForConfirmation_AndCancelChangesNothing()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Enforce");
        var cut = RenderIssuance(context);

        cut.Find("#pqc-stage").Change("Warn");

        Assert.Equal(AlgorithmPolicyGuidance.PqcOnlyScope, cut.Find("[data-test='pqc-only-confirm-scope']").TextContent.Trim());
        Assert.NotEmpty(cut.FindAll("[data-test='pqc-stage-confirm']"));
        cut.Find("[data-test='pqc-stage-cancel']").Click();

        Assert.Empty(cut.FindAll("[data-test='pqc-stage-confirm']"));
        Assert.DoesNotContain(Requests(context), r => r.Path == "/v1/settings/pqc-stage");
        Assert.Equal(PqcStageGuidance.Sentence(PqcStage.Enforce), cut.Find("[data-test='pqc-stage-help']").TextContent.Trim());
    }

    [Fact]
    public async Task Settings_ConfirmingALooserStage_CallsTheStageEndpoint()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Enforce");
        var cut = RenderIssuance(context);

        cut.Find("#pqc-stage").Change("Warn");
        cut.Find("[data-test='pqc-stage-apply']").Click();

        cut.WaitForAssertion(() =>
        {
            var call = Assert.Single(Requests(context), r => r.Path == "/v1/settings/pqc-stage");
            Assert.Equal(HttpMethod.Put, call.Method);
            Assert.Equal("""{"stage":"Warn"}""", call.Body);
            Assert.Equal(PqcStageGuidance.Sentence(PqcStage.Warn), cut.Find("[data-test='pqc-stage-help']").TextContent.Trim());
        });
    }

    [Fact]
    public async Task Settings_TighteningTheStage_DoesNotAsk_AndCallsTheStageEndpoint()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Warn");
        var cut = RenderIssuance(context);

        cut.Find("#pqc-stage").Change("Enforce");

        Assert.Empty(cut.FindAll("[data-test='pqc-stage-confirm']"));
        cut.WaitForAssertion(() => Assert.Single(Requests(context), r => r.Path == "/v1/settings/pqc-stage"));
    }

    [Fact]
    public async Task Settings_NonAdmin_SeesTheStageReadOnly()
    {
        await using var context = SettingsPageHarness.NewContext(admin: false, pqcStage: "Pilot");
        var cut = RenderIssuance(context);

        Assert.NotNull(cut.Find("#pqc-stage").GetAttribute("disabled"));
        Assert.Contains("Only an administrator can change this.", cut.Markup);
    }

    [Fact]
    public async Task Settings_SaveDoesNotChangeTheStageThroughTheGeneralSaveEndpoint()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Enforce");
        var cut = RenderIssuance(context);

        cut.Find("#pqc-stage").Change("Warn");
        cut.Find("[data-test='pqc-stage-apply']").Click();
        cut.WaitForAssertion(() => Assert.Single(Requests(context), r => r.Path == "/v1/settings/pqc-stage"));

        Assert.DoesNotContain(Requests(context), r => r.Method == HttpMethod.Put && r.Path == "/v1/settings");
    }
}
