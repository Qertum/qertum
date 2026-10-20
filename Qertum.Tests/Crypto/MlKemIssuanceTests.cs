using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Crypto;

/// <summary>
/// An ML-KEM leaf issued by a real CA of each signing family: the certificate carries the KEM key
/// under its NIST OID, asserts only <c>keyEncipherment</c> whatever the template asked for, and the
/// key the CA generated and stored is the one the certificate names — proven by encapsulating to
/// the certificate and decapsulating with the stored key, since a KEM key cannot sign a probe.
/// </summary>
public sealed class MlKemIssuanceTests : IDisposable
{
    private readonly IDataProtectionProvider _dataProtection = new EphemeralDataProtectionProvider();
    private readonly List<string> _directories = [];

    public static TheoryData<string, string> SetsUnderEachIssuer
    {
        get
        {
            var data = new TheoryData<string, string>();
            foreach (var issuer in new[] { "RSA", "ECDSA-P256", "ML-DSA-65", "MLDSA65-ECDSA-P256-SHA512" })
            foreach (var set in new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
                data.Add(issuer, set);
            return data;
        }
    }

    public void Dispose()
    {
        foreach (var directory in _directories.Where(Directory.Exists))
            try { Directory.Delete(directory, recursive: true); } catch { /* best effort */ }
    }

    [Theory]
    [MemberData(nameof(SetsUnderEachIssuer))]
    public void IssuedLeafCarriesTheKemKeyWithKeyEnciphermentOnly(string issuer, string set)
    {
        var generator = NewCa(Parse(issuer));
        var template = new CertificateTemplate
        {
            TypeKey = "SMIME",
            // A template written for signature keys: none of these bits may survive onto a KEM key
            // except keyEncipherment.
            KeyUsagesJson = """["DigitalSignature","NonRepudiation","KeyEncipherment"]""",
            ExtendedKeyUsagesJson = """["1.3.6.1.5.5.7.3.4"]"""
        };

        var issued = generator.GenerateCertificate(
            new CertificateRequest { CommonName = "kem.example.test", Type = "SMIME", KeyAlgorithm = Parse(set) },
            new CaSettings { PqcStage = PqcStage.Off }, template);

        var leaf = QertumKeyCodec.ReadCertificatePem(issued.CertificatePem)!;
        var root = QertumKeyCodec.ReadCertificatePem(generator.GetCaCertificatePem())!;
        leaf.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root)));

        Assert.Equal(OidOf(set), leaf.SubjectPublicKeyInfo.Algorithm.Algorithm.Id);
        Assert.Contains(X509Extensions.KeyUsage.Id, leaf.GetCriticalExtensionOids());
        Assert.Equal(KeyUsage.KeyEncipherment, KeyUsage.GetInstance(leaf.GetExtensionParsedValue(X509Extensions.KeyUsage)).IntValue);
        Assert.False(BasicConstraints.GetInstance(leaf.GetExtensionParsedValue(X509Extensions.BasicConstraints)).IsCA());
        Assert.Equal(Parse(set), CertificateGenerator.DetectAlgorithmFromCertificatePem(issued.CertificatePem));

        AssertStoredKeyDecapsulatesForTheCertificate(leaf, issued.PrivateKeyPem);
    }

    // Renewal and every re-issue go through the same generation: each issuance is a fresh key.
    [Fact]
    public void EachIssuanceGeneratesAFreshKey()
    {
        var generator = NewCa(CertificateKeyAlgorithm.EcdsaP256);
        var request = new CertificateRequest { CommonName = "kem.example.test", KeyAlgorithm = Parse("ML-KEM-768") };

        var first = generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off });
        var second = generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off });

        Assert.NotEqual(
            QertumKeyCodec.ReadCertificatePem(first.CertificatePem)!.SubjectPublicKeyInfo.GetEncoded(),
            QertumKeyCodec.ReadCertificatePem(second.CertificatePem)!.SubjectPublicKeyInfo.GetEncoded());
    }

    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void GenerateCa_RefusesAnMlKemRoot(string set)
    {
        var generator = NewGenerator(NewDirectory());

        Assert.Throws<NotSupportedException>(() => generator.GenerateCa(
            new GenerateCaRequest { CommonName = "KEM Root", KeyAlgorithm = Parse(set), ValidityDays = 365 }));
        Assert.False(generator.IsInitialized);
    }

    private static void AssertStoredKeyDecapsulatesForTheCertificate(X509Certificate leaf, string privateKeyPem)
    {
        var publicKey = Assert.IsType<MLKemPublicKeyParameters>(QertumKeyCodec.PublicKeyOf(leaf));
        var privateKey = Assert.IsType<MLKemPrivateKeyParameters>(QertumKeyCodec.ReadPrivateKeyPem(privateKeyPem));

        var encapsulator = new MLKemEncapsulator(publicKey.Parameters);
        encapsulator.Init(new ParametersWithRandom(publicKey, new SecureRandom()));
        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var sent = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sent, 0, sent.Length);

        var decapsulator = new MLKemDecapsulator(privateKey.Parameters);
        decapsulator.Init(privateKey);
        var received = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, received, 0, received.Length);

        Assert.Equal(sent, received);
    }

    private static string OidOf(string set) => set switch
    {
        "ML-KEM-512" => "2.16.840.1.101.3.4.4.1",
        "ML-KEM-768" => "2.16.840.1.101.3.4.4.2",
        "ML-KEM-1024" => "2.16.840.1.101.3.4.4.3",
        _ => throw new ArgumentOutOfRangeException(nameof(set))
    };

    private static CertificateKeyAlgorithm Parse(string canonical) =>
        CertificateKeyAlgorithmExtensions.Parse(canonical)
        ?? throw new InvalidOperationException($"{canonical} is not a recognised algorithm.");

    private CertificateGenerator NewCa(CertificateKeyAlgorithm algorithm)
    {
        var generator = NewGenerator(NewDirectory());
        generator.GenerateCa(new GenerateCaRequest { CommonName = $"{algorithm} Root", KeyAlgorithm = algorithm, ValidityDays = 365 });
        return generator;
    }

    private CertificateGenerator NewGenerator(string directory) =>
        new(_dataProtection, new CaDataOptions { Directory = directory }, NullLogger<CertificateGenerator>.Instance);

    private string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        _directories.Add(directory);
        return directory;
    }
}
