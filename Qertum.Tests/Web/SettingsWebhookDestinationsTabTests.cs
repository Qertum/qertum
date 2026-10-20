using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// Webhook destination rules are an admin-only CA setting (the API requires <c>admin-role</c>), so
/// they live on a Settings tab that only admins see; the Webhooks page only authors subscriptions.
/// </summary>
public sealed class SettingsWebhookDestinationsTabTests
{
    [Fact]
    public async Task AdminSeesTheWebhookDestinationsTabAndItsPanel()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true);
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-webhooks")));
        cut.Find("#settings-tab-webhooks").Click();

        cut.WaitForAssertion(() => Assert.NotNull(cut.Find("#destination-public-mode")));
        Assert.NotNull(cut.Find("[data-test='destination-policy-applies-immediately']"));
    }

    [Fact]
    public async Task SettingsEditorWithoutAdminDoesNotSeeTheTab()
    {
        await using var context = SettingsPageHarness.NewContext();
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-system")));
        Assert.Empty(cut.FindAll("#settings-tab-webhooks"));
    }

    [Fact]
    public async Task DeepLinkToTheTabFallsBackForANonAdmin()
    {
        await using var context = SettingsPageHarness.NewContext();
        var nav = context.Services.GetRequiredService<NavigationManager>();
        nav.NavigateTo(nav.GetUriWithQueryParameter("section", "webhooks"));
        var cut = context.Render<Settings>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-authority")));
        Assert.Equal("true", cut.Find("#settings-tab-authority").GetAttribute("aria-selected"));
        Assert.Empty(cut.FindAll("#destination-public-mode"));
    }
}
