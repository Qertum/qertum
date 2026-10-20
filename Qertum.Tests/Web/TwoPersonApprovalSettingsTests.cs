using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class TwoPersonApprovalSettingsTests
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
    public void ShowsTheCurrentState_AndWhatItDoes()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireTwoPersonApproval: true);
        var cut = RenderIssuance(context);

        Assert.Equal(["off", "on"], cut.FindAll("#two-person-approval option").Select(o => o.GetAttribute("value")).ToArray());
        Assert.NotNull(cut.Find("#two-person-approval option[value='on']").GetAttribute("selected"));
        Assert.Contains("second administrator", cut.Find("[data-test='two-person-approval-help']").TextContent);
    }

    [Fact]
    public void ANonAdmin_SeesItReadOnly()
    {
        using var context = SettingsPageHarness.NewContext(admin: false);
        var cut = RenderIssuance(context);

        Assert.NotNull(cut.Find("#two-person-approval").GetAttribute("disabled"));
    }

    [Fact]
    public void TurningItOn_WarnsAboutASingleAdministratorFirst_AndCancelSendsNothing()
    {
        using var context = SettingsPageHarness.NewContext(admin: true);
        var cut = RenderIssuance(context);

        cut.Find("#two-person-approval").Change("on");

        Assert.Contains("only one administrator", cut.Find("[data-test='two-person-approval-confirm']").TextContent);
        cut.Find("[data-test='two-person-approval-cancel']").Click();
        Assert.Empty(cut.FindAll("[data-test='two-person-approval-confirm']"));
        Assert.DoesNotContain(Requests(context), r => r.Path == "/v1/settings/two-person-approval");
    }

    [Fact]
    public void ConfirmingOn_PutsTheAdminEndpoint()
    {
        using var context = SettingsPageHarness.NewContext(admin: true);
        var cut = RenderIssuance(context);

        cut.Find("#two-person-approval").Change("on");
        cut.Find("[data-test='two-person-approval-apply']").Click();

        cut.WaitForAssertion(() =>
        {
            var put = Assert.Single(Requests(context), r => r.Path == "/v1/settings/two-person-approval");
            Assert.Equal(HttpMethod.Put, put.Method);
            Assert.Equal("{\"enabled\":true}", put.Body);
        });
    }

    [Fact]
    public void TurningItOff_AppliesAtOnce()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireTwoPersonApproval: true);
        var cut = RenderIssuance(context);

        cut.Find("#two-person-approval").Change("off");

        Assert.Empty(cut.FindAll("[data-test='two-person-approval-confirm']"));
        cut.WaitForAssertion(() => Assert.Equal("{\"enabled\":false}",
            Assert.Single(Requests(context), r => r.Path == "/v1/settings/two-person-approval").Body));
    }
}
