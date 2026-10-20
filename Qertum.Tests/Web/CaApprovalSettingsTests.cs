using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class CaApprovalSettingsTests
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
    public void ShowsTheCurrentModeAndBothChoices()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireIndependentCaApproval: true);
        var cut = RenderIssuance(context);

        Assert.Equal(["independent", "waived"], cut.FindAll("#ca-approval option").Select(o => o.GetAttribute("value")).ToArray());
        Assert.Contains("someone other than", cut.Find("[data-test='ca-approval-help']").TextContent);
    }

    [Fact]
    public void ANonAdmin_SeesItReadOnly()
    {
        using var context = SettingsPageHarness.NewContext(admin: false);
        var cut = RenderIssuance(context);

        Assert.NotNull(cut.Find("#ca-approval").GetAttribute("disabled"));
    }

    [Fact]
    public void Waiving_AsksFirst_AndCancelSendsNothing()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireIndependentCaApproval: true);
        var cut = RenderIssuance(context);

        cut.Find("#ca-approval").Change("waived");
        Assert.NotEmpty(cut.FindAll("[data-test='ca-approval-confirm']"));
        cut.Find("[data-test='ca-approval-cancel']").Click();

        Assert.Empty(cut.FindAll("[data-test='ca-approval-confirm']"));
        Assert.DoesNotContain(Requests(context), r => r.Path == "/v1/settings/ca-approval");
    }

    [Fact]
    public void ConfirmingWaive_PutsTheAdminEndpoint()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireIndependentCaApproval: true);
        var cut = RenderIssuance(context);

        cut.Find("#ca-approval").Change("waived");
        cut.Find("[data-test='ca-approval-apply']").Click();

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Method == HttpMethod.Put && r.Path == "/v1/settings/ca-approval" && r.Body!.Contains("\"requireIndependentApproval\":false")));
    }

    [Fact]
    public void Requiring_AppliesAtOnce_WithoutAConfirmation()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, requireIndependentCaApproval: false);
        var cut = RenderIssuance(context);

        cut.Find("#ca-approval").Change("independent");

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Path == "/v1/settings/ca-approval" && r.Body!.Contains("\"requireIndependentApproval\":true")));
        Assert.Empty(cut.FindAll("[data-test='ca-approval-confirm']"));
    }
}
