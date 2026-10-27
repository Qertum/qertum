using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class RevokedIssuerSettingsTests
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
        using var context = SettingsPageHarness.NewContext(admin: true, revokedIssuer: "Retire");
        var cut = RenderIssuance(context);

        Assert.Equal(["HardStop", "Retire"], cut.FindAll("#revoked-issuer option").Select(o => o.GetAttribute("value")).ToArray());
        Assert.Contains("one of them can be made the default", cut.Find("[data-test='revoked-issuer-help']").TextContent);
    }

    [Fact]
    public void ANonAdmin_SeesItReadOnly()
    {
        using var context = SettingsPageHarness.NewContext(admin: false);
        var cut = RenderIssuance(context);

        Assert.NotNull(cut.Find("#revoked-issuer").GetAttribute("disabled"));
    }

    [Fact]
    public void MovingToRetire_AsksFirst_AndCancelSendsNothing()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, revokedIssuer: "HardStop");
        var cut = RenderIssuance(context);

        cut.Find("#revoked-issuer").Change("Retire");
        Assert.NotEmpty(cut.FindAll("[data-test='revoked-issuer-confirm']"));
        cut.Find("[data-test='revoked-issuer-cancel']").Click();

        Assert.Empty(cut.FindAll("[data-test='revoked-issuer-confirm']"));
        Assert.DoesNotContain(Requests(context), r => r.Path == "/v1/settings/revoked-issuer");
    }

    [Fact]
    public void ConfirmingRetire_PutsTheAdminEndpoint()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, revokedIssuer: "HardStop");
        var cut = RenderIssuance(context);

        cut.Find("#revoked-issuer").Change("Retire");
        cut.Find("[data-test='revoked-issuer-apply']").Click();

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Method == HttpMethod.Put && r.Path == "/v1/settings/revoked-issuer" && r.Body!.Contains("\"mode\":\"Retire\"")));
    }

    [Fact]
    public void MovingToHardStop_AppliesAtOnce_WithoutAConfirmation()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, revokedIssuer: "Retire");
        var cut = RenderIssuance(context);

        cut.Find("#revoked-issuer").Change("HardStop");

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Path == "/v1/settings/revoked-issuer" && r.Body!.Contains("\"mode\":\"HardStop\"")));
        Assert.Empty(cut.FindAll("[data-test='revoked-issuer-confirm']"));
    }
}
