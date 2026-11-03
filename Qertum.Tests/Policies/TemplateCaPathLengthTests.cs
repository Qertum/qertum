using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Policies;

/// <summary>
/// A CA certificate issued from a template (KeyCertSign) had cA=true with no path length, so it could create further CA
/// levels; the issuer ceremony sets one. Template-issued CAs now carry pathLenConstraint 0 (AI Scan #346 on 1.0.0-rc4.2).
/// </summary>
public sealed class TemplateCaPathLengthTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); } catch { /* best effort */ }
    }

    [Theory]
    [InlineData("""["KeyCertSign","CrlSign","DigitalSignature"]""", true)]
    [InlineData("""["DigitalSignature","KeyEncipherment"]""", false)]
    public void ATemplateCa_CanSignLeavesOnly(string keyUsages, bool expectCa)
    {
        var generator = new CertificateGenerator(new EphemeralDataProtectionProvider(), new CaDataOptions { Directory = _directory },
            NullLogger<CertificateGenerator>.Instance);
        generator.GenerateCa(new GenerateCaRequest { CommonName = "Root", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256, ValidityDays = 365 });
        var template = new CertificateTemplate { TypeKey = "SubordinateCA", KeyUsagesJson = keyUsages, ValidityDays = 30 };

        var issued = generator.GenerateCertificate(
            new CertificateRequest { CommonName = "sub.example.test", Type = "SubordinateCA", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256 },
            new CaSettings { PqcStage = PqcStage.Off }, template);

        var constraints = BasicConstraints.GetInstance(
            QertumKeyCodec.ReadCertificatePem(issued.CertificatePem)!.GetExtensionParsedValue(X509Extensions.BasicConstraints));
        Assert.Equal(expectCa, constraints.IsCA());
        if (expectCa) Assert.Equal(0, constraints.PathLenConstraintInteger!.IntValueExact);
        else Assert.Null(constraints.PathLenConstraintInteger);
    }
}
