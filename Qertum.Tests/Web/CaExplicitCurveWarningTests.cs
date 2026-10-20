using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// An ECDSA root written before the named-curve fix cannot anchor an OpenSSL 3 chain, and nothing in
/// Qertum can repair it in place, so the Authority tab says so beside the algorithm.
/// </summary>
public sealed class CaExplicitCurveWarningTests
{
    [Fact]
    public async Task AuthorityTab_WarnsWhenTheRootUsesExplicitCurveParameters()
    {
        await using var context = SettingsPageHarness.NewContext(
            """{"isInitialized":true,"algorithm":"ECDSA-P256","explicitCurveParameters":true}""");
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='explicit-curve-parameters']")));

        Assert.Equal(CaStatusResponse.ExplicitCurveParametersWarning,
            cut.Find("[data-test='explicit-curve-parameters']").TextContent.Trim());
    }

    [Fact]
    public async Task AuthorityTab_SaysNothingForANamedCurveRoot()
    {
        await using var context = SettingsPageHarness.NewContext(
            """{"isInitialized":true,"algorithm":"ECDSA-P256","explicitCurveParameters":false}""");
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.Contains("ECDSA-P256", cut.Markup, StringComparison.Ordinal));

        Assert.Empty(cut.FindAll("[data-test='explicit-curve-parameters']"));
    }
}
