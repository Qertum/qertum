using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>
/// Every CA signature has to be produced through <see cref="ICaSigner"/>, because that is the seam a
/// key living outside the process plugs into. A signing path that reaches for the private key
/// directly still works today and silently cannot be backed by a vault tomorrow — these tests are
/// what catch that.
/// </summary>
public sealed class CaSignerTests : IDisposable
{
    private readonly string _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
    private readonly RecordingCaSignerFactory _signers = new();
    // One provider for the whole test: ca.key is written encrypted, so a second generator reading it
    // back has to share the key ring that wrote it.
    private readonly IDataProtectionProvider _dataProtection = new EphemeralDataProtectionProvider();
    private readonly CertificateGenerator _generator;

    public CaSignerTests()
    {
        _generator = new CertificateGenerator(
            _dataProtection,
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance,
            _signers.Create);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "Signer Seam Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void RootCertificate_IsSelfSignedThroughTheSigner()
    {
        // The root is produced the same way every later certificate is, not by a one-off path.
        Assert.Equal(1, _signers.Single.SignatureFactoriesCreated);
    }

    [Fact]
    public void IssuingALeafCertificate_SignsThroughTheSigner()
    {
        var before = _signers.Single.SignatureFactoriesCreated;

        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "leaf.contoso.local", Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        Assert.Equal(before + 1, _signers.Single.SignatureFactoriesCreated);

        // And the result is a real certificate signed by the CA, not merely a call that happened.
        var caCert = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(_generator.GetCaCertificatePem()));
        var leaf = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(issued.CertificatePem));
        leaf.Verify(caCert.GetPublicKey());
    }

    [Fact]
    public void BuildingACrl_SignsThroughTheSigner()
    {
        var before = _signers.Single.SignatureFactoriesCreated;

        _generator.GenerateCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 1);

        Assert.Equal(before + 1, _signers.Single.SignatureFactoriesCreated);
    }

    [Fact]
    public void BuildingADeltaCrl_SignsThroughTheSigner()
    {
        var before = _signers.Single.SignatureFactoriesCreated;

        _generator.GenerateDeltaCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1);

        Assert.Equal(before + 1, _signers.Single.SignatureFactoriesCreated);
    }

    [Fact]
    public void AnsweringOcsp_SignsThroughTheSignerAndNamesItsPublicKey()
    {
        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "ocsp-seam.contoso.local", Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off });

        var caCert = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(_generator.GetCaCertificatePem()));
        var requestGenerator = new OcspReqGenerator();
        requestGenerator.AddRequest(new CertificateID(
            new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(
                Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, Org.BouncyCastle.Asn1.DerNull.Instance),
            caCert,
            new Org.BouncyCastle.Math.BigInteger(issued.SerialNumber, 16)));

        var before = _signers.Single.SignatureFactoriesCreated;

        var der = _generator.GenerateOcspResponse(
            requestGenerator.Generate().GetEncoded(),
            new Dictionary<string, OcspCertificateStatus> { [issued.SerialNumber] = OcspCertificateStatus.Good });

        Assert.Equal(before + 1, _signers.Single.SignatureFactoriesCreated);

        var basic = (BasicOcspResp)new OcspResp(der).GetResponseObject();
        Assert.True(basic.Verify(caCert.GetPublicKey()));
    }

    [Fact]
    public void ReloadingFromDisk_RebuildsTheSignerThroughTheSameFactory()
    {
        // A second generator over the same CaData directory loads ca.key and must hand it to the
        // factory rather than signing with it directly.
        var reloadSigners = new RecordingCaSignerFactory();
        var reloaded = new CertificateGenerator(
            _dataProtection,
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance,
            reloadSigners.Create);

        reloaded.GenerateCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2);

        Assert.Equal(1, reloadSigners.Single.SignatureFactoriesCreated);
    }

    /// <summary>Hands out signers that delegate to the real local one while counting what they are asked for.</summary>
    private sealed class RecordingCaSignerFactory
    {
        private readonly List<RecordingCaSigner> _created = [];

        public ICaSigner Create(AsymmetricCipherKeyPair keyPair)
        {
            var signer = new RecordingCaSigner(new LocalKeyPairCaSigner(keyPair));
            _created.Add(signer);
            return signer;
        }

        /// <summary>The one signer built so far; fails the test if a path built its own instead.</summary>
        public RecordingCaSigner Single => Assert.Single(_created);
    }

    private sealed class RecordingCaSigner(ICaSigner inner) : ICaSigner
    {
        public int SignatureFactoriesCreated { get; private set; }

        public AsymmetricKeyParameter PublicKey => inner.PublicKey;

        public string SignatureAlgorithm => inner.SignatureAlgorithm;

        public ISignatureFactory CreateSignatureFactory()
        {
            SignatureFactoriesCreated++;
            return inner.CreateSignatureFactory();
        }
    }
}
