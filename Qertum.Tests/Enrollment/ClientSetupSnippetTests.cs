using Qertum.Services;
using Qertum.Web.Components.Pages.Enrollment;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// The copy-paste setup examples the enrollment wizard shows. These are instructions an operator
/// runs verbatim, so they must carry the deployment's own URLs and must never carry a credential.
/// </summary>
public sealed class ClientSetupSnippetTests
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

    [Fact]
    public void Acme_CoversTheClientsTheWizardOffers()
    {
        var snippets = ClientSetupSnippets.ForAcme(Acme());

        Assert.Equal(["certbot", "cert-manager", "acme.sh"], snippets.Select(s => s.Id));
    }

    [Fact]
    public void Est_CoversTheClientsTheWizardOffers()
    {
        var snippets = ClientSetupSnippets.ForEst(Est());

        Assert.Equal(["curl", "estclient"], snippets.Select(s => s.Id));
    }

    [Fact]
    public void EverySnippet_UsesTheConfiguredUrlAndNeverAHardcodedOne()
    {
        // A deployment behind a proxy sets its own public URLs; an example naming any other host
        // sends the operator's client somewhere that is not this CA.
        var snippets = ClientSetupSnippets.ForAcme(Acme()).Concat(ClientSetupSnippets.ForEst(Est()));

        Assert.All(snippets, s =>
        {
            Assert.True(s.Command.Contains(Directory, StringComparison.Ordinal)
                     || s.Command.Contains(EstBase, StringComparison.Ordinal),
                $"{s.Id} names neither configured URL");
            Assert.DoesNotContain("example.com", s.Command, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("localhost", s.Command, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void Acme_WithoutExternalAccountBinding_OmitsTheEabFlags()
    {
        var snippets = ClientSetupSnippets.ForAcme(Acme(eab: false));

        Assert.All(snippets, s => Assert.DoesNotContain("eab", s.Command, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Acme_WithExternalAccountBinding_ShowsPlaceholdersNotCredentials()
    {
        var snippets = ClientSetupSnippets.ForAcme(Acme(eab: true));

        Assert.All(snippets, s => Assert.Contains("eab", s.Command, StringComparison.OrdinalIgnoreCase));
        // The MAC key exists only in the one-time create response on the admin page. The example
        // must leave a blank for the operator, never fetch or embed anything.
        Assert.All(snippets, s => Assert.Contains("<", s.Command, StringComparison.Ordinal));
    }

    [Fact]
    public void Est_ShowsCredentialPlaceholdersRatherThanAnyStoredCredential()
    {
        var curl = ClientSetupSnippets.ForEst(Est()).Single(s => s.Id == "curl");

        Assert.Contains("<username>", curl.Command, StringComparison.Ordinal);
        Assert.Contains("<password>", curl.Command, StringComparison.Ordinal);
    }

    [Fact]
    public void EverySnippet_ReferencesTheDownloadedRootCertificateSoTlsCanBeVerified()
    {
        // Every one of these clients fails the handshake until the root is trusted, so an example
        // that skips the trust step teaches the operator to reach for an insecure flag instead.
        var snippets = ClientSetupSnippets.ForAcme(Acme()).Concat(ClientSetupSnippets.ForEst(Est()));

        Assert.All(snippets, s =>
            Assert.Contains(ClientSetupSnippets.RootCertificateFileName, s.Command, StringComparison.Ordinal));
    }

    [Fact]
    public void NoSnippet_TeachesTheOperatorToSkipCertificateVerification()
    {
        var snippets = ClientSetupSnippets.ForAcme(Acme(eab: true)).Concat(ClientSetupSnippets.ForEst(Est()));

        Assert.All(snippets, s =>
        {
            Assert.DoesNotContain("--insecure", s.Command, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("-k ", s.Command, StringComparison.Ordinal);
            Assert.DoesNotContain("insecureSkipVerify", s.Command, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void TrustBootstrap_InstallsTheDownloadedRootOnEachPlatform()
    {
        var steps = ClientSetupSnippets.TrustBootstrap();

        Assert.Equal(["linux", "macos", "windows"], steps.Select(s => s.Id));
        Assert.All(steps, s => Assert.Contains(ClientSetupSnippets.RootCertificateFileName, s.Command, StringComparison.Ordinal));
    }
}
