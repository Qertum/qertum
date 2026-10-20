using System.Net;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// A composite root cannot be validated by any relying party without composite support, and the
/// choice is only undone by replacing the root. Onboarding therefore says so before Generate, and
/// keeps Generate disabled until the operator confirms.
/// </summary>
public sealed class OnboardingCompositeRootTests
{
    [Fact]
    public async Task EveryCompositeCombinationIsOfferedForTheRoot()
    {
        await using var context = NewContext();
        var cut = OpenGenerateStep(context);

        var offered = cut.FindAll("#gen-algo option").Select(o => o.GetAttribute("value")).ToHashSet();

        Assert.All(Enum.GetValues<CertificateKeyAlgorithm>().Where(a => a.GetFamily() == AlgorithmFamily.Composite),
            a => Assert.Contains(a.ToCanonicalString(), offered));
    }

    [Fact]
    public async Task ACompositeRootIsBlockedUntilTheNoticeIsConfirmed()
    {
        await using var context = NewContext();
        var cut = OpenGenerateStep(context);
        Assert.Empty(cut.FindAll("[data-test='composite-root-notice']"));

        cut.Find("#gen-algo").Change("MLDSA65-ECDSA-P256-SHA512");

        Assert.Equal(CertificateAlgorithmSummary.CompositeRootNotice,
            cut.Find("[data-test='composite-root-notice'] p").TextContent.Trim());
        Assert.True(GenerateButton(cut).HasAttribute("disabled"));

        cut.Find("#composite-root-confirm").Change(true);
        Assert.False(GenerateButton(cut).HasAttribute("disabled"));

        // Choosing another algorithm withdraws the confirmation.
        cut.Find("#gen-algo").Change("MLDSA87-ECDSA-P384-SHA512");
        Assert.True(GenerateButton(cut).HasAttribute("disabled"));
    }

    [Fact]
    public async Task AClassicalRootNeedsNoConfirmation_WhenTheStageAllowsIt()
    {
        await using var context = NewContext();
        var cut = OpenGenerateStep(context);

        cut.Find("#gen-stage").Change("Off");
        cut.Find("#gen-algo").Change("ECDSA-P384");

        Assert.Empty(cut.FindAll("[data-test='composite-root-notice']"));
        Assert.False(GenerateButton(cut).HasAttribute("disabled"));
    }

    private static BunitContext NewContext()
    {
        var context = new BunitContext();
        // The page gates its offline-root card on the admin role.
        context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit).SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new NotFoundHandler()) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private static IRenderedComponent<Onboarding> OpenGenerateStep(BunitContext context)
    {
        var cut = context.Render<Onboarding>();
        cut.FindAll("button.option-card").Single(b => b.TextContent.Contains("Generate new CA", StringComparison.Ordinal)).Click();
        return cut;
    }

    private static AngleSharp.Dom.IElement GenerateButton(IRenderedComponent<Onboarding> cut) =>
        cut.Find("button.ob-btn-submit");

    // The CA status call fails, which onboarding treats as "not configured yet".
    private sealed class NotFoundHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
