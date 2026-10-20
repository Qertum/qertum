using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// "PQC-only" reads as "this deployment is post-quantum". It is not: the setting governs the keys
/// in certificates this CA issues and nothing else. ACME account signatures, the identity service's
/// token signatures and the TLS transport (whose key exchange is what harvest-now-decrypt-later
/// attacks target) are all untouched, and the Settings page says so where the switch is.
/// </summary>
public sealed class PqcOnlyScopeTests
{
    [Fact]
    public void ScopeNote_NamesEachThingTheSettingDoesNotChange()
    {
        var note = AlgorithmPolicyGuidance.PqcOnlyScope;

        Assert.Contains("ACME", note, StringComparison.Ordinal);
        Assert.Contains("identity service", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TLS", note, StringComparison.Ordinal);
        Assert.Contains("key exchange", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("harvest-now-decrypt-later", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AllowedAlgorithms_NamesEveryPostQuantumAlgorithmTheCaAccepts()
    {
        // The help text listed "ML-DSA-65/87" and went stale the day ML-DSA-44 and SLH-DSA shipped.
        // Deriving it from the enum is what keeps the next algorithm from repeating that.
        var text = AlgorithmPolicyGuidance.PqcOnlyAllowedAlgorithms;

        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>().Where(a => a.GetFamily() == AlgorithmFamily.Pqc))
            Assert.Contains(algorithm.ToCanonicalString(), text, StringComparison.Ordinal);
        Assert.Contains("paired", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("composite", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssuanceTab_ShowsTheScopeBesideTheSwitch()
    {
        await using var context = SettingsPageHarness.NewContext();
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-issuance")));
        cut.Find("#settings-tab-issuance").Click();

        Assert.Equal(AlgorithmPolicyGuidance.PqcOnlyScope, cut.Find("[data-test='pqc-only-scope']").TextContent.Trim());
        Assert.Contains(AlgorithmPolicyGuidance.PqcOnlyAllowedAlgorithms, cut.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public async Task LoosenConfirmation_RepeatsTheScope()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Enforce");
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-issuance")));
        cut.Find("#settings-tab-issuance").Click();
        cut.Find("#pqc-stage").Change("Off");

        Assert.Equal(AlgorithmPolicyGuidance.PqcOnlyScope, cut.Find("[data-test='pqc-only-confirm-scope']").TextContent.Trim());
    }
}
