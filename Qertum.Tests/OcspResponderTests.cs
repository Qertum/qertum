using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>
/// Exercises the OCSP responder against a real CA: every response here is parsed back with
/// BouncyCastle and its signature checked against the CA certificate, so a response that is
/// well-formed but signed wrong still fails.
/// </summary>
public sealed class OcspResponderTests : IDisposable
{
    private readonly CertificateGenerator _generator;
    private readonly string _caDataDir;
    private readonly X509Certificate _caCertificate;

    public OcspResponderTests()
    {
        _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "OCSP Test Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });

        _caCertificate = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(_generator.GetCaCertificatePem()));
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void GoodCertificate_IsReportedGoodAndSignedByTheCa()
    {
        var issued = IssueCertificate("good.contoso.local");
        var request = BuildRequest(issued.SerialNumber);

        var single = SingleResponse(_generator.GenerateOcspResponse(
            request, Statuses(issued.SerialNumber, OcspCertificateStatus.Good)));

        Assert.Null(single.GetCertStatus());
    }

    [Fact]
    public void ResponderId_IsTheHashOfTheCaKey()
    {
        var issued = IssueCertificate("responder-id.contoso.local");

        var response = (BasicOcspResp)new OcspResp(_generator.GenerateOcspResponse(
            BuildRequest(issued.SerialNumber), Statuses(issued.SerialNumber, OcspCertificateStatus.Good))).GetResponseObject();

        // RFC 6960 §4.2.2.3 byKey. The generator builds this from the CA certificate's SPKI rather than
        // from a key object, so it must stay byte-identical to BouncyCastle's key-based RespID.
        Assert.Equal(new RespID(_caCertificate.GetPublicKey()), response.ResponderId);
    }

    [Fact]
    public void RevokedCertificate_ReportsRevocationTimeAndReason()
    {
        var issued = IssueCertificate("revoked.contoso.local");
        var revokedAt = DateTime.UtcNow.AddHours(-3);
        var request = BuildRequest(issued.SerialNumber);

        var single = SingleResponse(_generator.GenerateOcspResponse(request, Statuses(
            issued.SerialNumber,
            new OcspCertificateStatus(OcspCertificateState.Revoked, revokedAt, "keyCompromise"))));

        var status = Assert.IsType<RevokedStatus>(single.GetCertStatus());
        Assert.Equal(revokedAt.ToString("u"), status.RevocationTime.ToUniversalTime().ToString("u"));
        Assert.True(status.HasRevocationReason);
        Assert.Equal(Org.BouncyCastle.Asn1.X509.CrlReason.KeyCompromise, status.RevocationReason);
    }

    [Fact]
    public void SerialWithNoRecord_IsUnknownRatherThanGood()
    {
        var issued = IssueCertificate("unlisted.contoso.local");
        var request = BuildRequest(issued.SerialNumber);

        // The caller found no row for this serial, so the status dictionary is empty. Answering
        // "good" here would vouch for a certificate this CA has no record of issuing.
        var single = SingleResponse(_generator.GenerateOcspResponse(
            request, new Dictionary<string, OcspCertificateStatus>()));

        Assert.IsType<UnknownStatus>(single.GetCertStatus());
    }

    [Fact]
    public void CertIdFromAnotherIssuer_IsUnknownEvenWhenTheSerialMatches()
    {
        var issued = IssueCertificate("elsewhere.contoso.local");

        // A second CA that happens to be asked about a serial our CA did issue.
        var foreignDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var foreignGenerator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = foreignDir },
                NullLogger<CertificateGenerator>.Instance);
            foreignGenerator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "Other Root CA",
                KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
                ValidityDays = 365
            });
            var foreignCa = new X509CertificateParser().ReadCertificate(
                System.Text.Encoding.UTF8.GetBytes(foreignGenerator.GetCaCertificatePem()));

            var request = BuildRequest(issued.SerialNumber, issuer: foreignCa);

            var single = SingleResponse(_generator.GenerateOcspResponse(
                request, Statuses(issued.SerialNumber, OcspCertificateStatus.Good)));

            Assert.IsType<UnknownStatus>(single.GetCertStatus());
        }
        finally
        {
            if (Directory.Exists(foreignDir))
                try { Directory.Delete(foreignDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Nonce_IsEchoedBackToTheClient()
    {
        var issued = IssueCertificate("nonce.contoso.local");
        var nonce = Guid.NewGuid().ToByteArray();

        var generator = new OcspReqGenerator();
        generator.AddRequest(new CertificateID(Sha1, _caCertificate, SerialOf(issued)));
        generator.SetRequestExtensions(new Org.BouncyCastle.Asn1.X509.X509Extensions(
            new Dictionary<Org.BouncyCastle.Asn1.DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>
            {
                [OcspObjectIdentifiers.PkixOcspNonce] =
                    new(false, new Org.BouncyCastle.Asn1.DerOctetString(new Org.BouncyCastle.Asn1.DerOctetString(nonce)))
            }));

        var basic = BasicResponse(_generator.GenerateOcspResponse(
            generator.Generate().GetEncoded(), Statuses(issued.SerialNumber, OcspCertificateStatus.Good)));

        var echoed = basic.ResponseExtensions?.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        Assert.NotNull(echoed);
        Assert.Contains(Convert.ToHexString(nonce), Convert.ToHexString(echoed.Value.GetOctets()));
    }

    [Fact]
    public void MultipleSerialsInOneRequest_EachGetTheirOwnStatus()
    {
        var good = IssueCertificate("multi-good.contoso.local");
        var revoked = IssueCertificate("multi-revoked.contoso.local");

        var generator = new OcspReqGenerator();
        generator.AddRequest(new CertificateID(Sha1, _caCertificate, SerialOf(good)));
        generator.AddRequest(new CertificateID(Sha1, _caCertificate, SerialOf(revoked)));

        var statuses = new Dictionary<string, OcspCertificateStatus>
        {
            [good.SerialNumber] = OcspCertificateStatus.Good,
            [revoked.SerialNumber] = new(OcspCertificateState.Revoked, DateTime.UtcNow.AddMinutes(-5), "superseded")
        };

        var responses = BasicResponse(
            _generator.GenerateOcspResponse(generator.Generate().GetEncoded(), statuses)).Responses;

        Assert.Equal(2, responses.Length);
        Assert.Null(responses[0].GetCertStatus());
        Assert.IsType<RevokedStatus>(responses[1].GetCertStatus());
    }

    [Fact]
    public void ReadOcspRequestSerials_ReturnsTheStoredSerialFormat()
    {
        var issued = IssueCertificate("serials.contoso.local");

        var serials = _generator.ReadOcspRequestSerials(BuildRequest(issued.SerialNumber));

        // The endpoint looks rows up by CertificateRequest.SerialNumber, so the formats must match
        // exactly — uppercase hex with no leading zero.
        Assert.Equal([issued.SerialNumber], serials);
    }

    [Fact]
    public void IssuedCertificate_CarriesTheAuthorityInformationAccessExtension()
    {
        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "aia.contoso.local", Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org", OcspResponderUrl = "http://ca.contoso.local/ocsp" });

        using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2
            .CreateFromPem(issued.CertificatePem);

        // Without AIA nothing tells a relying party the responder exists.
        var aia = cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "1.3.6.1.5.5.7.1.1");
        Assert.NotNull(aia);
        Assert.False(aia.Critical);

        var parsed = new System.Security.Cryptography.X509Certificates.X509AuthorityInformationAccessExtension(
            aia.RawData, aia.Critical);
        Assert.Equal(["http://ca.contoso.local/ocsp"], parsed.EnumerateOcspUris());
    }

    [Fact]
    public void IssuedCertificate_OmitsTheExtensionWhenNoResponderIsConfigured()
    {
        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "no-aia.contoso.local", Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2
            .CreateFromPem(issued.CertificatePem);

        Assert.DoesNotContain(cert.Extensions, e => e.Oid?.Value == "1.3.6.1.5.5.7.1.1");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static readonly Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier Sha1 =
        new(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, Org.BouncyCastle.Asn1.DerNull.Instance);

    private GeneratedCertificate IssueCertificate(string commonName) =>
        _generator.GenerateCertificate(
            new CertificateRequest { CommonName = commonName, Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

    private static Org.BouncyCastle.Math.BigInteger SerialOf(GeneratedCertificate issued) =>
        new(issued.SerialNumber, 16);

    private byte[] BuildRequest(string serialHex, X509Certificate? issuer = null)
    {
        var generator = new OcspReqGenerator();
        generator.AddRequest(new CertificateID(
            Sha1,
            issuer ?? _caCertificate,
            new Org.BouncyCastle.Math.BigInteger(serialHex, 16)));
        return generator.Generate().GetEncoded();
    }

    private static Dictionary<string, OcspCertificateStatus> Statuses(string serial, OcspCertificateStatus status) =>
        new() { [serial] = status };

    private BasicOcspResp BasicResponse(byte[] der)
    {
        var response = new OcspResp(der);
        Assert.Equal(OcspRespStatus.Successful, response.Status);

        var basic = (BasicOcspResp)response.GetResponseObject();
        Assert.True(basic.Verify(_caCertificate.GetPublicKey()),
            "OCSP response is not signed by the CA that issued the certificate.");
        return basic;
    }

    private SingleResp SingleResponse(byte[] der) => Assert.Single(BasicResponse(der).Responses);
}
