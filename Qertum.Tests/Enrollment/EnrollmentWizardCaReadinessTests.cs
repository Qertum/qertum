using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// Onboarding's "Generate" only files a Root CA request, so between that and its approval there is a
/// window where nothing can be signed. The API refuses a request filed in that window; the wizard must
/// not walk someone through the form first.
/// </summary>
public sealed class EnrollmentWizardCaReadinessTests
{
    [Fact]
    public async Task RootCaStillPending_ShowsTheBlockerAndNoWizard()
    {
        await using var host = new WizardTestHost();
        var pendingId = Guid.NewGuid();
        host.Api.CaStatus = new CaStatusResponse { IsInitialized = false, PendingRootCaRequestId = pendingId };

        var cut = host.Context.Render<NewCertificateRequest>();

        cut.WaitForElement("[data-state='ca-not-ready']");
        Assert.Empty(cut.FindAll("[data-purpose='WebServer']"));
        Assert.Contains($"/certificate-requests/{pendingId}", cut.Markup);
    }

    [Fact]
    public async Task NoCaAtAll_PointsAtOnboarding()
    {
        await using var host = new WizardTestHost();
        host.Api.CaStatus = new CaStatusResponse { IsInitialized = false };

        var cut = host.Context.Render<NewCertificateRequest>();

        cut.WaitForElement("[data-state='ca-not-ready']");
        Assert.Contains("/onboarding", cut.Markup);
    }

    [Fact]
    public async Task CaReady_RendersTheWizard()
    {
        await using var host = new WizardTestHost();

        var cut = host.Context.Render<NewCertificateRequest>();

        cut.WaitForElement("[data-purpose='WebServer']");
        Assert.Empty(cut.FindAll("[data-state='ca-not-ready']"));
    }
}
