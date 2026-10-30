using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Web;

/// <summary>
/// What an administrator is told when the CA certificate is revoked: the revoke dialog says it stops the CA, and
/// onboarding says why it is asking for a new root instead of looking like a first-time setup.
/// </summary>
public sealed class RevokedCaWebTests
{
    private static CertificateRequest Issued(string type) => new()
    {
        Id = new CertificateRequestId(Guid.NewGuid()),
        CommonName = "Acme Lab Root CA",
        Type = type,
        RequestedBy = "admin",
        Status = CertificateRequestStatus.Issued,
        ValidFrom = DateTime.UtcNow.AddDays(-1),
        ValidTo = DateTime.UtcNow.AddDays(300)
    };

    private static BunitContext NewContext(HttpMessageHandler handler, bool admin = true)
    {
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();
        var auth = context.AddAuthorization().SetAuthorized("alice");
        if (admin) auth.SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(handler) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private sealed class Stub(Func<string, string?> body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var json = body(request.RequestUri!.AbsolutePath);
            return Task.FromResult(json is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") });
        }
    }

    private static async Task<IRenderedComponent<CertificateDetail>> OpenRevokeDialogAsync(CertificateRequest request)
    {
        var context = NewContext(new Stub(path => path == $"/v1/certificate-requests/{request.Id}"
            ? JsonSerializer.Serialize(request, JsonSerializerOptions.Web) : null));
        var cut = context.Render<CertificateDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        await Task.Yield();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("button.btn-danger")));
        cut.Find("button.btn-danger").Click();
        return cut;
    }

    [Fact]
    public async Task RevokingTheRootCa_WarnsThatTheCaStopsIssuing()
    {
        var cut = await OpenRevokeDialogAsync(Issued(WellKnownCertificateTypes.RootCa));

        var warning = cut.Find("[data-test='revoke-ca-warning']").TextContent;
        Assert.Contains("stops the CA from issuing", warning);
        Assert.Contains("CRL and OCSP", warning);
        Assert.Contains("until it is renewed", warning);
    }

    [Fact]
    public async Task RevokingAnOrdinaryCertificate_ShowsNoCaWarning()
    {
        var cut = await OpenRevokeDialogAsync(Issued("WebServer"));

        Assert.Empty(cut.FindAll("[data-test='revoke-ca-warning']"));
        Assert.Empty(cut.FindAll("[data-test='revoke-subordinate-ca-warning']"));
    }

    [Fact]
    public async Task RevokingASubordinateCa_WarnsThatItsCertificatesAndIssuingStop()
    {
        var cut = await OpenRevokeDialogAsync(Issued("SubordinateCA"));

        var warning = cut.Find("[data-test='revoke-subordinate-ca-warning']").TextContent;
        Assert.Contains("every certificate it signed", warning);
        Assert.Contains("stops signing", warning);
        Assert.Empty(cut.FindAll("[data-test='revoke-ca-warning']"));
    }

    [Fact]
    public async Task RevokingACaCertificateFromAnotherTemplate_IsRecognisedByItsBasicConstraints()
    {
        var request = Issued("PartnerIssuingCA");
        request.CertificatePem = SelfSignedPem(certificateAuthority: true);

        var cut = await OpenRevokeDialogAsync(request);

        Assert.NotEmpty(cut.FindAll("[data-test='revoke-subordinate-ca-warning']"));
    }

    private static string SelfSignedPem(bool certificateAuthority)
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var csr = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Partner Issuing CA", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        csr.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension(
            certificateAuthority, false, 0, true));
        using var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return cert.ExportCertificatePem();
    }

    [Theory]
    [InlineData(IssuerKind.Intermediate, "/issuers?valid=0")]
    [InlineData(IssuerKind.Root, "/revoked")]
    [InlineData(null, "/revoked")]
    public void Banner_RenewLink_GoesWhereThatKindOfCaRenews(IssuerKind? kind, string href) =>
        Assert.Equal(href, Qertum.Web.Components.Layout.CaRevokedBanner.RenewHref(kind));

    [Fact]
    public void OnboardingAfterARevokedCa_SaysWhy()
    {
        using var context = NewContext(new Stub(path => path == "/v1/ca/status"
            ? """{"isInitialized":false,"issuerRevoked":true}""" : null));

        var cut = context.Render<Onboarding>();

        cut.WaitForAssertion(() => Assert.Contains("was revoked", cut.Find("[data-test='issuer-revoked-notice']").TextContent));
        Assert.Contains("renew the revoked root certificate", cut.Find("[data-test='issuer-revoked-notice']").TextContent);
    }

    [Fact]
    public void FirstTimeOnboarding_HasNoRevokedNotice()
    {
        using var context = NewContext(new Stub(path => path == "/v1/ca/status"
            ? """{"isInitialized":false,"issuerRevoked":false}""" : null));

        var cut = context.Render<Onboarding>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='offline-root-card']")));
        Assert.Empty(cut.FindAll("[data-test='issuer-revoked-notice']"));
    }
}
