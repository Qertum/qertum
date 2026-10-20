using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Web;

/// <summary>
/// The detail page must report the subject key algorithm and the issuer signature algorithm as two
/// labelled fields. With one field called "Signature Algorithm" an ML-DSA certificate issued by the
/// RSA CA presented itself as RSA, and .NET has no friendly name for the post-quantum signature
/// OIDs, so for a PQC-signed certificate that single field rendered blank.
/// </summary>
public sealed class CertificateDetailAlgorithmFieldsTests
{
    [Fact]
    public async Task PqcCertificateUnderAClassicalIssuer_NamesBothAlgorithmsAndWarnsAboutThePath()
    {
        var request = IssuedRequest("ML-DSA-65", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Contains("Subject Public Key Algorithm", cut.Markup));
        Assert.Contains("Issuer Signature Algorithm", cut.Markup);

        Assert.Equal("ML-DSA-65", FieldValue(cut, "subject-key-algorithm"));
        Assert.Contains("RSA", FieldValue(cut, "issuer-signature-algorithm"), StringComparison.OrdinalIgnoreCase);

        // The whole point: the operator must not read the issuer's RSA signature as the subject key.
        Assert.Contains("not fully post-quantum", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PqcCertificateUnderAPqcIssuer_NamesTheIssuerAlgorithmInsteadOfRenderingBlank()
    {
        var request = IssuedRequest("ML-DSA-65", caAlgorithm: "ML-DSA-87");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("ML-DSA-87", FieldValue(cut, "issuer-signature-algorithm")));
        Assert.Equal("ML-DSA-65", FieldValue(cut, "subject-key-algorithm"));

        // Post-quantum end to end is still only authentication.
        Assert.Contains("key exchange", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ClassicalCertificateUnderAClassicalIssuer_ShowsBothFieldsAndNoPathWarning()
    {
        var request = IssuedRequest("ECDSA-P256", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("ECDSA-P256", FieldValue(cut, "subject-key-algorithm")));
        Assert.Contains("RSA", FieldValue(cut, "issuer-signature-algorithm"), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("post-quantum", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PairedIssuance_LabelsEachCertificateWithItsOwnKeyRatherThanThePairsName()
    {
        // Neither certificate of a pair holds a "HYBRID-ECDSA-P256" key: one is ECDSA P-256, the
        // other ML-DSA-65. Labelling either card with the pair's name names a key that is not there.
        var request = IssuedHybridRequest(caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("ECDSA-P256", FieldValue(cut, "subject-key-algorithm")));
        Assert.Equal("ML-DSA-65", FieldValue(cut, "pqc-subject-key-algorithm"));
        Assert.Contains("RSA", FieldValue(cut, "pqc-issuer-signature-algorithm"), StringComparison.OrdinalIgnoreCase);

        // The classical half carries no post-quantum claim; the PQC half is under a classical issuer.
        Assert.Contains("not fully post-quantum", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PairedIssuance_DownloadMenuSaysItsFormatsCarryOnlyTheClassicalCertificate()
    {
        var request = IssuedHybridRequest(caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));

        // The menu is closed on load; the note lives inside it, beside the formats it qualifies.
        cut.Find("[data-test='download-menu-toggle']").Click();

        var note = cut.Find("[data-test='paired-download-note']").TextContent;
        Assert.Contains("classical", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PairedIssuance_SaysThePairIsNeitherCompositeNorHybridTlsAuthentication()
    {
        // Two certificates for one subject reads as "hybrid", and "hybrid" reads as protection
        // against the break of either algorithm. A relying party validates one of the pair, so the
        // bundle is only as strong as the leg that relying party accepts.
        var request = IssuedHybridRequest(caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='paired-scope-note']")));
        var note = cut.Find("[data-test='paired-scope-note']").TextContent;
        Assert.Equal(CertificateAlgorithmSummary.PairedIssuanceScopeNote, note.Trim());
    }

    [Fact]
    public async Task ASingleCertificate_HasNoPairedScopeNote()
    {
        var request = IssuedRequest("ML-DSA-65", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));

        Assert.Empty(cut.FindAll("[data-test='paired-scope-note']"));
    }

    [Fact]
    public async Task ASingleCertificate_HasNoPairedDownloadNote()
    {
        var request = IssuedRequest("ECDSA-P256", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));

        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.Empty(cut.FindAll("[data-test='paired-download-note']"));
    }

    [Fact]
    public async Task OpenDownloadMenu_RaisesItsCardAboveTheCardsBelowIt()
    {
        // Each detail card is its own stacking context, so the menu's z-index cannot escape the
        // card; without lifting the card, the history card below paints over the menu.
        var request = IssuedRequest("ECDSA-P256", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));

        Assert.DoesNotContain("detail-card-raised", cut.Find("[data-test='certificate-data-card']").ClassList);

        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.Contains("detail-card-raised", cut.Find("[data-test='certificate-data-card']").ClassList);
    }

    [Fact]
    public async Task CompositeCertificate_IsBadgedAndScopedAsCompositeAndWarnsAboutPkcs12()
    {
        var request = IssuedRequest("MLDSA65-ECDSA-P256-SHA512", caAlgorithm: "MLDSA87-ECDSA-P384-SHA512");
        request.HasPrivateKey = true;

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("MLDSA65-ECDSA-P256-SHA512", FieldValue(cut, "subject-key-algorithm")));
        Assert.Equal("MLDSA87-ECDSA-P384-SHA512", FieldValue(cut, "issuer-signature-algorithm"));
        Assert.Contains("Composite", FieldValue(cut, "composite-badge"), StringComparison.Ordinal);
        Assert.Equal(CertificateAlgorithmSummary.CompositeScopeNote, FieldValue(cut, "composite-scope-note"));
        Assert.Contains("post-quantum end to end", FieldValue(cut, "certification-path-note"), StringComparison.Ordinal);

        cut.Find("[data-test='download-menu-toggle']").Click();
        Assert.Equal(DownloadFormatGuidance.CompositePkcs12Note, FieldValue(cut, "composite-pkcs12-note"));
    }

    [Theory]
    [InlineData("ML-DSA-65")]
    [InlineData("SLH-DSA-SHA2-128F")]
    public async Task PqcOnlyCertificate_OffersPkcs12WithItsImporterNote(string algorithm)
    {
        var request = IssuedRequest(algorithm, caAlgorithm: "RSA");
        request.HasPrivateKey = true;

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));
        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.NotEmpty(cut.FindAll("[data-format-hint='pfx']"));
        Assert.Equal(DownloadFormatGuidance.PqcPkcs12Note, FieldValue(cut, "pqc-pkcs12-note"));
    }

    [Fact]
    public async Task MlKemCertificateUnderAClassicalIssuer_IsBadgedScopedAndSaysTheBindingIsClassical()
    {
        var request = IssuedRequest("ML-KEM-768", caAlgorithm: "RSA");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("ML-KEM-768", FieldValue(cut, "subject-key-algorithm")));
        Assert.Equal("ML-KEM · Full PQC (encryption)", FieldValue(cut, "kem-badge"));
        Assert.Empty(cut.FindAll("[data-test='pqc-only-badge']"));
        Assert.Equal(CertificateAlgorithmSummary.KemScopeNote, FieldValue(cut, "kem-scope-note"));
        var pathNote = FieldValue(cut, "certification-path-note");
        Assert.Contains("ML-KEM", pathNote, StringComparison.Ordinal);
        Assert.Contains("classical signature", pathNote, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MlKemCertificate_OffersPkcs12WithItsOwnImporterNote()
    {
        var request = IssuedRequest("ML-KEM-512", caAlgorithm: "RSA");
        request.HasPrivateKey = true;

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));
        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.NotEmpty(cut.FindAll("[data-format-hint='pfx']"));
        Assert.Equal(DownloadFormatGuidance.KemPkcs12Note, FieldValue(cut, "kem-pkcs12-note"));
        Assert.Empty(cut.FindAll("[data-test='pqc-pkcs12-note']"));
    }

    // The signature-key note ("covers authentication only: no post-quantum key exchange") is wrong
    // for a KEM key, whose whole purpose is key establishment.
    [Fact]
    public async Task MlKemCertificateUnderAPqcIssuer_ClaimsCmsKeyEstablishmentButNotTls()
    {
        var request = IssuedRequest("ML-KEM-1024", caAlgorithm: "ML-DSA-65");

        var cut = await RenderDetailAsync(request);

        cut.WaitForAssertion(() => Assert.Equal("ML-DSA-65", FieldValue(cut, "issuer-signature-algorithm")));
        var pathNote = FieldValue(cut, "certification-path-note");
        Assert.DoesNotContain("authentication only", pathNote, StringComparison.Ordinal);
        Assert.Contains("CMS key establishment only", pathNote, StringComparison.Ordinal);
        Assert.Contains("does not change TLS key exchange", pathNote, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ASingleClassicalCertificate_HasNoCompositeNotes()
    {
        var request = IssuedRequest("ECDSA-P256", caAlgorithm: "RSA");
        request.HasPrivateKey = true;

        var cut = await RenderDetailAsync(request);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));
        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.Empty(cut.FindAll("[data-test='composite-scope-note']"));
        Assert.Empty(cut.FindAll("[data-test='composite-pkcs12-note']"));
        Assert.Empty(cut.FindAll("[data-test='pqc-pkcs12-note']"));
        Assert.Empty(cut.FindAll("[data-test='kem-scope-note']"));
        Assert.Empty(cut.FindAll("[data-test='kem-badge']"));
    }

    [Fact]
    public async Task APair_LabelsTheSigningAndTheEncryptionCertificateWithTheirOwnKeys()
    {
        var cut = await RenderDetailAsync(IssuedPairRequest(caAlgorithm: "RSA"));

        cut.WaitForAssertion(() => Assert.Equal("ML-DSA-65", FieldValue(cut, "subject-key-algorithm")));
        Assert.Equal("ML-KEM-768", FieldValue(cut, "pqc-subject-key-algorithm"));
        Assert.Contains("Signing", FieldValue(cut, "pair-badge"), StringComparison.Ordinal);
        Assert.Contains("Encryption Certificate", cut.Find("[data-test='pair-card'] .detail-card-title").TextContent, StringComparison.Ordinal);
        Assert.DoesNotContain("PQC Certificate", cut.Markup, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APair_SaysItIsTwoIndependentCertificates_AndNotTheHybridWording()
    {
        var cut = await RenderDetailAsync(IssuedPairRequest(caAlgorithm: "RSA"));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='pair-scope-note']")));
        Assert.Equal(CertificateAlgorithmSummary.PairScopeNote, FieldValue(cut, "pair-scope-note"));
        Assert.Empty(cut.FindAll("[data-test='paired-scope-note']"));
        Assert.Empty(cut.FindAll("[data-test='paired-download-note']"));
    }

    [Fact]
    public async Task TheEncryptionCertificateOfAPair_SaysCmsKeyEstablishmentAndNotTls()
    {
        var cut = await RenderDetailAsync(IssuedPairRequest(caAlgorithm: "ML-DSA-87"));

        cut.WaitForAssertion(() => Assert.Equal("ML-KEM-768", FieldValue(cut, "pqc-subject-key-algorithm")));
        var note = FieldValue(cut, "pqc-certification-path-note");
        Assert.Contains("CMS key establishment only", note, StringComparison.Ordinal);
        Assert.DoesNotContain("authentication only", note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APairsDownloadMenu_NamesTheSigningCertificate_WithTheMlDsaImporterNote()
    {
        var cut = await RenderDetailAsync(IssuedPairRequest(caAlgorithm: "RSA"));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='subject-key-algorithm']")));
        cut.Find("[data-test='download-menu-toggle']").Click();

        Assert.Equal(DownloadFormatGuidance.PairDownloadNote, FieldValue(cut, "pair-download-note"));
        Assert.Equal(DownloadFormatGuidance.PqcPkcs12Note, FieldValue(cut, "pqc-pkcs12-note"));
    }

    [Fact]
    public async Task TheEncryptionCardOfAPair_CarriesTheMlKemImporterNote()
    {
        var cut = await RenderDetailAsync(IssuedPairRequest(caAlgorithm: "RSA"));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='pair-card']")));

        Assert.Equal(DownloadFormatGuidance.KemPkcs12Note, FieldValue(cut, "pair-kem-pkcs12-note"));
    }

    private static string FieldValue(IRenderedComponent<CertificateDetail> cut, string testId) =>
        cut.Find($"[data-test='{testId}']").TextContent.Trim();

    private static async Task<IRenderedComponent<CertificateDetail>> RenderDetailAsync(CertificateRequest request)
    {
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();
        context.AddAuthorization().SetAuthorized("alice");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new RequestStub(request)) { BaseAddress = new Uri("http://api.test/") }));

        var cut = context.Render<CertificateDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        await Task.Yield();
        return cut;
    }

    /// <summary>
    /// An Issued request carrying a real certificate signed by a real CA of the given algorithm —
    /// the issuer signature OID has to come off an actual certificate, not a constant.
    /// </summary>
    private static CertificateRequest IssuedRequest(string subjectAlgorithm, string caAlgorithm)
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);
            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = $"{caAlgorithm} Issuing CA",
                KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(caAlgorithm)!.Value,
                ValidityDays = 365
            });

            var algorithm = CertificateKeyAlgorithmExtensions.Parse(subjectAlgorithm)!.Value;
            var issued = generator.GenerateCertificate(
                new CertificateRequest
                {
                    CommonName = "leaf.contoso.local",
                    Type = "WebServer",
                    KeyAlgorithm = algorithm
                },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

            return new CertificateRequest
            {
                Id = Guid.NewGuid(),
                CommonName = "leaf.contoso.local",
                Type = "WebServer",
                Status = CertificateRequestStatus.Issued,
                KeyAlgorithm = algorithm,
                CertificatePem = issued.CertificatePem,
                ValidFrom = issued.ValidFrom,
                ValidTo = issued.ValidTo
            };
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>An Issued paired-issuance request: two real certificates from one generator call.</summary>
    private static CertificateRequest IssuedHybridRequest(string caAlgorithm)
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);
            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = $"{caAlgorithm} Issuing CA",
                KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(caAlgorithm)!.Value,
                ValidityDays = 365
            });

            var issued = generator.GenerateCertificate(
                new CertificateRequest
                {
                    CommonName = "paired.contoso.local",
                    Type = "WebServer",
                    KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP256
                },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

            Assert.False(string.IsNullOrWhiteSpace(issued.PqcCertificatePem),
                "paired issuance must produce a PQC certificate for this test to mean anything");

            return new CertificateRequest
            {
                Id = Guid.NewGuid(),
                CommonName = "paired.contoso.local",
                Type = "WebServer",
                Status = CertificateRequestStatus.Issued,
                KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP256,
                CertificatePem = issued.CertificatePem,
                PqcCertificatePem = issued.PqcCertificatePem,
                ValidFrom = issued.ValidFrom,
                ValidTo = issued.ValidTo
            };
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    /// <summary>An Issued signing + encryption pair: two real certificates from one generator call.</summary>
    private static CertificateRequest IssuedPairRequest(string caAlgorithm, CertificateKeyAlgorithm pair = CertificateKeyAlgorithm.PairMlDsa65MlKem768)
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);
            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = $"{caAlgorithm} Issuing CA",
                KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(caAlgorithm)!.Value,
                ValidityDays = 365
            });

            var issued = generator.GenerateCertificate(
                new CertificateRequest { CommonName = "mail-pair.contoso.local", Type = "SMIME", KeyAlgorithm = pair },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });
            Assert.False(string.IsNullOrWhiteSpace(issued.PqcCertificatePem));

            return new CertificateRequest
            {
                Id = Guid.NewGuid(),
                CommonName = "mail-pair.contoso.local",
                Type = "SMIME",
                Status = CertificateRequestStatus.Issued,
                KeyAlgorithm = pair,
                CertificatePem = issued.CertificatePem,
                PqcCertificatePem = issued.PqcCertificatePem,
                HasPrivateKey = true,
                HasPqcPrivateKey = true,
                ValidFrom = issued.ValidFrom,
                ValidTo = issued.ValidTo
            };
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    private sealed class RequestStub(params CertificateRequest[] requests) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var match = requests.FirstOrDefault(r =>
                request.Method == HttpMethod.Get &&
                request.RequestUri!.AbsolutePath == $"/v1/certificate-requests/{r.Id}");

            return Task.FromResult(match is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(match, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
                });
        }
    }
}
