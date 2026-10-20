using Bunit;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// The secret-storage switch decides whether the CA key survives a move to new hardware, and it
/// does not reach the identity provider. The System tab says both where the switch is.
/// </summary>
public sealed class SecretStorageScopeTests
{
    [Fact]
    public async Task SystemTab_SaysWhatTheProviderProtectsAndThatTheIdentityProviderIsSeparate()
    {
        await using var context = SettingsPageHarness.NewContext();
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-system")));
        cut.Find("#settings-tab-system").Click();

        Assert.Contains("CA private key", cut.Markup, StringComparison.Ordinal);
        Assert.Contains("IdentityService:SecretStorageProvider", cut.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SystemTab_WarnsThatATpmSealedKeyDoesNotMoveToOtherHardware()
    {
        await using var context = SettingsPageHarness.NewContext();
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-system")));
        cut.Find("#settings-tab-system").Click();

        var warning = cut.Find("[data-test='tpm-portability']").TextContent;
        Assert.Contains("other hardware", warning, StringComparison.Ordinal);
    }
}
