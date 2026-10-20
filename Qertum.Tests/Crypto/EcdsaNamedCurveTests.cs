using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;

namespace Qertum.Tests.Crypto;

/// <summary>
/// RFC 5480 §2.1.1 requires an ECDSA key in PKIX to name its curve. Keys once carried explicit curve
/// parameters, which OpenSSL 3 refuses in a chain ("Certificate public key has explicit ECC
/// parameters"), so no Qertum ECDSA root could anchor an OpenSSL-validated chain.
/// </summary>
public sealed class EcdsaNamedCurveTests : IDisposable
{
    private readonly string _caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_caDir))
            try { Directory.Delete(_caDir, recursive: true); } catch { /* best effort */ }
    }

    public static TheoryData<CertificateKeyAlgorithm, string> Curves => new()
    {
        { CertificateKeyAlgorithm.EcdsaP256, SecObjectIdentifiers.SecP256r1.Id },
        { CertificateKeyAlgorithm.EcdsaP384, SecObjectIdentifiers.SecP384r1.Id }
    };

    [Theory]
    [MemberData(nameof(Curves))]
    public void GeneratedKeys_NameTheirCurveInThePublicAndPrivateKeyEncodings(CertificateKeyAlgorithm algorithm, string curveOid)
    {
        var keyPair = AlgorithmStrategyFactory.Create(algorithm).GenerateLeafKeyPair(new SecureRandom());

        var spkiParameters = QertumKeyCodec.ToSubjectPublicKeyInfo(keyPair.Public).Algorithm.Parameters.ToAsn1Object();
        var privateKeyParameters = QertumKeyCodec.ToPrivateKeyInfo(keyPair.Private).PrivateKeyAlgorithm.Parameters.ToAsn1Object();

        Assert.Equal(curveOid, Assert.IsType<DerObjectIdentifier>(spkiParameters).Id);
        Assert.Equal(curveOid, Assert.IsType<DerObjectIdentifier>(privateKeyParameters).Id);
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void GeneratedRoot_NamesItsCurveAndIsNotFlaggedInItsStatus(CertificateKeyAlgorithm algorithm, string curveOid)
    {
        var generator = GenerateRoot(algorithm);

        var root = QertumKeyCodec.ReadCertificatePem(generator.GetCaCertificatePem())!;

        Assert.Equal(curveOid, Assert.IsType<DerObjectIdentifier>(root.SubjectPublicKeyInfo.Algorithm.Parameters.ToAsn1Object()).Id);
        Assert.False(generator.GetCaStatus().ExplicitCurveParameters);
    }

    [Theory]
    [MemberData(nameof(Curves))]
    public void OpenSslVerifiesALeafUnderAnEcdsaRoot(CertificateKeyAlgorithm algorithm, string _)
    {
        var openSsl = OpenSslTool.Find() ?? throw SkipException("OpenSSL 3 is not installed.");
        var generator = GenerateRoot(algorithm);
        var leaf = generator.GenerateCertificate(new CertificateRequest
        {
            CommonName = "leaf.example.test",
            Type = "WebServer",
            KeyAlgorithm = algorithm
        }, caSettings: null);

        var rootPath = Path.Combine(_caDir, "root.pem");
        var leafPath = Path.Combine(_caDir, "leaf.pem");
        File.WriteAllText(rootPath, generator.GetCaCertificatePem());
        File.WriteAllText(leafPath, leaf.CertificatePem);

        var (exitCode, output) = OpenSslTool.Run(openSsl, $"verify -CAfile {rootPath} {leafPath}");

        Assert.True(exitCode == 0, output);
    }

    [Fact]
    public void ExplicitCurveParameters_AreDetectedOnlyForAnEcKeyWithoutANamedCurve()
    {
        Assert.True(CertificateGenerator.UsesExplicitCurveParameters(SelfSigned(explicitParameters: true)));
        Assert.False(CertificateGenerator.UsesExplicitCurveParameters(SelfSigned(explicitParameters: false)));
    }

    private CertificateGenerator GenerateRoot(CertificateKeyAlgorithm algorithm)
    {
        var generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDir },
            NullLogger<CertificateGenerator>.Instance);
        generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = $"{algorithm} Test Root CA",
            KeyAlgorithm = algorithm,
            ValidityDays = 365
        });
        return generator;
    }

    /// <summary>A self-signed P-256 certificate, its key encoded the way Qertum wrote keys before the fix, or named.</summary>
    private static X509Certificate SelfSigned(bool explicitParameters)
    {
        var curve = ECNamedCurveTable.GetByName("P-256")!;
        var generator = new ECKeyPairGenerator();
        generator.Init(explicitParameters
            ? new ECKeyGenerationParameters(new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H), new SecureRandom())
            : new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();

        var name = new X509Name("CN=Legacy Root");
        var builder = new X509V3CertificateGenerator();
        builder.SetSerialNumber(BigInteger.One);
        builder.SetIssuerDN(name);
        builder.SetSubjectDN(name);
        builder.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        builder.SetNotAfter(DateTime.UtcNow.AddDays(1));
        builder.SetPublicKey(keyPair.Public);
        return builder.Generate(QertumKeyCodec.SignatureFactoryFor(keyPair.Private));
    }

    private static Exception SkipException(string reason)
    {
        Assert.Skip(reason);
        return new InvalidOperationException(reason);
    }
}
