using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class IssuerStrengthSettingsTests
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
    public void ShowsTheCurrentModeAndAllChoices()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, issuerStrength: "Enforce");
        var cut = RenderIssuance(context);

        Assert.Equal(["Off", "Warn", "Enforce"], cut.FindAll("#issuer-strength option").Select(o => o.GetAttribute("value")).ToArray());
        Assert.Contains("refused", cut.Find("[data-test='issuer-strength-help']").TextContent);
        Assert.Contains("classical", cut.Find("[data-test='issuer-strength-help']").TextContent);
    }

    [Fact]
    public void ANonAdmin_SeesItReadOnly()
    {
        using var context = SettingsPageHarness.NewContext(admin: false);
        var cut = RenderIssuance(context);

        Assert.NotNull(cut.Find("#issuer-strength").GetAttribute("disabled"));
    }

    [Fact]
    public void Loosening_AsksFirst_AndCancelSendsNothing()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, issuerStrength: "Enforce");
        var cut = RenderIssuance(context);

        cut.Find("#issuer-strength").Change("Warn");
        Assert.NotEmpty(cut.FindAll("[data-test='issuer-strength-confirm']"));
        cut.Find("[data-test='issuer-strength-cancel']").Click();

        Assert.Empty(cut.FindAll("[data-test='issuer-strength-confirm']"));
        Assert.DoesNotContain(Requests(context), r => r.Path == "/v1/settings/issuer-strength");
    }

    [Fact]
    public void ConfirmingLoosen_PutsTheAdminEndpoint()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, issuerStrength: "Enforce");
        var cut = RenderIssuance(context);

        cut.Find("#issuer-strength").Change("Off");
        cut.Find("[data-test='issuer-strength-apply']").Click();

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Method == HttpMethod.Put && r.Path == "/v1/settings/issuer-strength" && r.Body!.Contains("\"mode\":\"Off\"")));
    }

    [Fact]
    public void Tightening_AppliesAtOnce_WithoutAConfirmation()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, issuerStrength: "Warn");
        var cut = RenderIssuance(context);

        cut.Find("#issuer-strength").Change("Enforce");

        cut.WaitForAssertion(() => Assert.Contains(Requests(context),
            r => r.Path == "/v1/settings/issuer-strength" && r.Body!.Contains("\"mode\":\"Enforce\"")));
        Assert.Empty(cut.FindAll("[data-test='issuer-strength-confirm']"));
    }
}
