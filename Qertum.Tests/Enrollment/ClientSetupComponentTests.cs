using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages.Enrollment;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The wizard's client-setup panel. It renders instructions an operator copies, so what it shows
/// must follow the configured deployment rather than any built-in default.
/// </summary>
public sealed class ClientSetupComponentTests
{
    private const string Directory = "https://acme.contoso.local/acme/directory";
    private const string EstBase = "https://est.contoso.local/.well-known/est";

    private static AcmeEnrollmentRoute Acme(bool eab = false) => new()
    {
        DirectoryUrl = Directory,
        TemplateTypeKey = "WebServer",
        ExternalAccountBindingRequired = eab,
        AutoApprove = true
    };

    private static EstEnrollmentRoute Est() => new()
    {
        BaseUrl = EstBase,
        TemplateTypeKey = "WebServer",
        AutoApprove = true
    };

    private static BunitContext Host()
    {
        var context = new BunitContext();
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        return context;
    }

    [Fact]
    public void Acme_RendersATabPerClient()
    {
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme()));

        Assert.Equal(["certbot", "cert-manager", "acme.sh"],
            cut.FindAll("[data-client]").Select(b => b.GetAttribute("data-client")));
    }

    [Fact]
    public void Est_RendersATabPerClient()
    {
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.EstProtocol)
            .Add(x => x.Est, Est()));

        Assert.Equal(["curl", "estclient"],
            cut.FindAll("[data-client]").Select(b => b.GetAttribute("data-client")));
    }

    [Fact]
    public void ShowsTheSelectedClientsCommandAndSwitchesOnClick()
    {
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme()));

        Assert.Contains("certbot register", cut.Find("[data-test='client-command']").TextContent);

        cut.Find("[data-client='cert-manager']").Click();

        Assert.Contains("ClusterIssuer", cut.Find("[data-test='client-command']").TextContent);
    }

    [Fact]
    public void TheRenderedCommandCarriesTheConfiguredDirectoryUrl()
    {
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme()));

        Assert.Contains(Directory, cut.Find("[data-test='client-command']").TextContent);
    }

    [Fact]
    public void LeadsWithTheTrustBootstrapStep()
    {
        // Every client below fails its handshake until the root is installed, so the download and
        // the install step have to come before the enrollment command, not after it.
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme()));

        Assert.NotEmpty(cut.FindAll("[data-test='download-root']"));
        Assert.Equal(["linux", "macos", "windows"],
            cut.FindAll("[data-platform]").Select(b => b.GetAttribute("data-platform")));
    }

    [Fact]
    public void RequestingTheRootCertificateIsDelegatedToThePage()
    {
        using var context = Host();
        var downloads = 0;

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme())
            .Add(x => x.OnDownloadRoot, () => downloads++));
        cut.Find("[data-test='download-root']").Click();

        Assert.Equal(1, downloads);
    }

    [Fact]
    public void AFailedRootDownloadIsShown()
    {
        // Silently failing would leave the operator installing nothing and blaming their client.
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme())
            .Add(x => x.DownloadError, "CA is not configured."));

        Assert.Contains("CA is not configured.", cut.Find("[data-test='root-download-error']").TextContent);
    }

    [Fact]
    public void WithExternalAccountBindingRequired_TheRenderedCommandLeavesTheKeyBlank()
    {
        using var context = Host();

        var cut = context.Render<ClientSetup>(p => p
            .Add(x => x.Protocol, RouteStep.AcmeProtocol)
            .Add(x => x.Acme, Acme(eab: true)));

        var command = cut.Find("[data-test='client-command']").TextContent;
        Assert.Contains("--eab-kid <kid>", command);
        // The `=` form: a base64url MAC key can start with '-', which certbot's argument parser reads as an option.
        Assert.Contains("--eab-hmac-key=<hmac-key>", command);
    }
}
