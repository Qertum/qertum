using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerUrlsTests : IDisposable
{
    private readonly IssuerTestKit _kit = new();

    public void Dispose() => _kit.Dispose();

    private static readonly CaSettings Settings = new()
    {
        CrlDistributionPoint = "https://ca.example/crl",
        CrlDeltaDistributionPoint = "https://ca.example/crl/delta",
        DeltaCrlEnabled = true,
        OcspResponderUrl = "https://ca.example/ocsp",
        PublicBaseUrl = "https://ca.example/"
    };

    [Fact]
    public void Legacy_GetsNoOverride()
    {
        Assert.Null(IssuerUrls.For(new Issuer { LegacyFiles = true }, Settings));
    }

    [Fact]
    public void NonLegacy_DerivesPerIssuerUrls()
    {
        var issuer = new Issuer { Id = new IssuerId(Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001")) };

        var urls = IssuerUrls.For(issuer, Settings)!;

        Assert.Equal("https://ca.example/crl/aaaaaaaa-0000-0000-0000-000000000001", urls.CrlDistributionPoint);
        Assert.Equal("https://ca.example/crl/delta/aaaaaaaa-0000-0000-0000-000000000001", urls.DeltaCrlDistributionPoint);
        Assert.Equal("https://ca.example/ocsp", urls.OcspResponderUrl);
        Assert.Equal("https://ca.example/v1/issuers/aaaaaaaa-0000-0000-0000-000000000001/certificate", urls.CaIssuersUrl);
    }

    [Fact]
    public void NonLegacy_ExplicitColumnsWin_AndNoBaseMeansNoCaIssuers()
    {
        var issuer = new Issuer { CrlDistributionPoint = "http://x/crl.der", OcspResponderUrl = "http://x/ocsp" };

        var urls = IssuerUrls.For(issuer, new CaSettings { PqcStage = PqcStage.Off })!;

        Assert.Equal("http://x/crl.der", urls.CrlDistributionPoint);
        Assert.Equal("http://x/ocsp", urls.OcspResponderUrl);
        Assert.Null(urls.CaIssuersUrl);
        Assert.Null(urls.DeltaCrlDistributionPoint);
    }

    [Fact]
    public void Leaf_FromANonLegacyIssuer_CarriesItsOwnUrls()
    {
        var generator = _kit.NewGenerator(new CaDataOptions { Directory = Path.Combine(_kit.CaDataDirectory, "x") });
        generator.GenerateCa(new GenerateCaRequest { CommonName = "X", ValidityDays = 365 });
        var urls = new IssuerUrls("http://c/crl/1", null, "http://c/ocsp", "http://c/v1/issuers/1/certificate");

        var leaf = ((ICertificateGenerator)generator).GenerateCertificate(
            new CertificateRequest { CommonName = "l.example" }, Settings, null, urls);

        var cert = QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!;
        Assert.Equal(["http://c/crl/1"], CdpUris(cert));
        var aia = AuthorityInformationAccess.GetInstance(
            X509ExtensionUtilities.FromExtensionValue(cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess)));
        Assert.Contains(aia.GetAccessDescriptions(), d => d.AccessMethod.Equals(AccessDescription.IdADCAIssuers));
        Assert.Contains(aia.GetAccessDescriptions(), d => d.AccessMethod.Equals(AccessDescription.IdADOcsp));
    }

    [Fact]
    public void Leaf_WithoutUrls_IsExactlyAsBefore()
    {
        var generator = _kit.NewGenerator(new CaDataOptions { Directory = Path.Combine(_kit.CaDataDirectory, "y") });
        generator.GenerateCa(new GenerateCaRequest { CommonName = "Y", ValidityDays = 365 });

        var leaf = generator.GenerateCertificate(new CertificateRequest { CommonName = "l.example" }, Settings);

        var cert = QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!;
        Assert.Equal(["https://ca.example/crl"], CdpUris(cert));
        var aia = AuthorityInformationAccess.GetInstance(
            X509ExtensionUtilities.FromExtensionValue(cert.GetExtensionValue(X509Extensions.AuthorityInfoAccess)));
        Assert.DoesNotContain(aia.GetAccessDescriptions(), d => d.AccessMethod.Equals(AccessDescription.IdADCAIssuers));
    }

    private static List<string> CdpUris(X509Certificate cert) =>
        CrlDistPoint.GetInstance(X509ExtensionUtilities.FromExtensionValue(cert.GetExtensionValue(X509Extensions.CrlDistributionPoints)))
            .GetDistributionPoints()
            .SelectMany(dp => GeneralNames.GetInstance(dp.DistributionPointName.Name).GetNames())
            .Select(n => n.Name.ToString()!)
            .ToList();
}
