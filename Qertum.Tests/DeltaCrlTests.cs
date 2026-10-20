using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Qertum.Services;
using CertificateRequest = Qertum.Services.CertificateRequest;
using BcCrl = Org.BouncyCastle.X509.X509Crl;

namespace Qertum.Tests;

/// <summary>
/// Regression tests for RFC 5280 §5.2.4 delta CRL support.
/// </summary>
public sealed class DeltaCrlTests : IDisposable
{
    private readonly CertificateGenerator _generator;
    private readonly string _caDataDir;

    public DeltaCrlTests()
    {
        _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "Test Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir)) Directory.Delete(_caDataDir, recursive: true);
    }

    private static BcCrl ParseCrl(byte[] der)
    {
        using var ms = new MemoryStream(der);
        return new X509CrlParser().ReadCrl(ms);
    }

    private static Org.BouncyCastle.Math.BigInteger? DeltaIndicatorOf(BcCrl crl)
    {
        var raw = crl.GetExtensionValue(X509Extensions.DeltaCrlIndicator);
        return raw is null
            ? null
            : CrlNumber.GetInstance(Asn1Object.FromByteArray(raw.GetOctets())).PositiveValue;
    }

    [Fact]
    public void DeltaCrl_CarriesTheDeltaCrlIndicatorNamingItsBase()
    {
        var delta = ParseCrl(_generator.GenerateDeltaCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1));

        Assert.Equal(1, DeltaIndicatorOf(delta)?.IntValue);
    }

    [Fact]
    public void DeltaCrl_OnlyContainsTheSuppliedEntries()
    {
        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "leaf.contoso.local", Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off });
        var leaf = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(issued.CertificatePem));

        var revoked = new CertificateRequest
        {
            CommonName = "leaf.contoso.local",
            CertificatePem = issued.CertificatePem,
            RevokedAtUtc = DateTime.UtcNow,
            RevocationReason = "superseded"
        };

        var delta = ParseCrl(_generator.GenerateDeltaCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1));

        Assert.NotNull(delta.GetRevokedCertificate(leaf.SerialNumber));
    }

    [Fact]
    public void DeltaCrl_CarriesItsOwnCrlNumber()
    {
        var raw = ParseCrl(_generator.GenerateDeltaCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 9, baseCrlNumber: 1))
            .GetExtensionValue(X509Extensions.CrlNumber);
        var number = CrlNumber.GetInstance(Asn1Object.FromByteArray(raw!.GetOctets())).PositiveValue;

        Assert.Equal(9, number.IntValue);
    }
}
