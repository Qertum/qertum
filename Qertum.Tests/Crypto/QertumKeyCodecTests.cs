using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;
using RawPemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;

namespace Qertum.Tests.Crypto;

/// <summary>
/// The codec is the one place keys cross to and from bytes. For composite keys it must produce the
/// draft's encodings; for every other algorithm it must be indistinguishable from calling
/// BouncyCastle directly — the parity half is what lets call sites move behind it without changing
/// a single certificate, key file or OCSP response.
/// </summary>
public sealed class QertumKeyCodecTests
{
    private static readonly SecureRandom Random = new();

    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    public static TheoryData<string> BouncyCastleAlgorithms => ["RSA", "ECDSA-P256", "ML-DSA-65", "SLH-DSA-SHA2-128F"];

    // ---- composite ----

    [Theory]
    [MemberData(nameof(Names))]
    public void PublishedCertificateVerifiesThroughTheCodec(string name)
    {
        var certificate = new X509CertificateParser().ReadCertificate(Vector(name).Certificate);

        certificate.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(certificate)));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void CompositePrivateKeyPemIsThePublishedPkcs8(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var vector = CompositeTestVectors.For(algorithm);

        var pem = QertumKeyCodec.WritePrivateKeyPem(CompositePrivateKey.Decode(algorithm, vector.PrivateKey));

        using var reader = new StringReader(pem);
        var pemObject = new RawPemReader(reader).ReadPemObject();
        Assert.Equal("PRIVATE KEY", pemObject.Type);
        Assert.Equal(vector.PrivateKeyPkcs8, pemObject.Content);
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void PublishedPkcs8ReadsBackAsTheCompositeKey(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var vector = CompositeTestVectors.For(algorithm);
        var pem = "-----BEGIN PRIVATE KEY-----\n"
                  + Convert.ToBase64String(vector.PrivateKeyPkcs8, Base64FormattingOptions.InsertLineBreaks)
                  + "\n-----END PRIVATE KEY-----\n";

        var key = Assert.IsType<CompositePrivateKey>(QertumKeyCodec.ReadPrivateKeyPem(pem));

        Assert.Equal(vector.PrivateKey, key.GetEncoded());
    }

    [Theory]
    [InlineData("MLDSA65-ECDSA-P256-SHA512")]
    [InlineData("MLDSA65-RSA4096-PKCS15-SHA512")]
    [InlineData("MLDSA87-Ed448-SHAKE256")]
    public void CompositeKeysWorkEndToEndThroughTheCodec(string name)
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName(name)!, Random);
        var subject = new X509Name("CN=codec");

        var certificate = SelfSigned(keys, subject);
        var csr = new Pkcs10CertificationRequest(
            QertumKeyCodec.SignatureFactoryFor(keys.Private), subject, QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public), null);
        var reloaded = QertumKeyCodec.ReadPrivateKeyPem(QertumKeyCodec.WritePrivateKeyPem(keys.Private));

        certificate.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(certificate)));
        Assert.True(QertumKeyCodec.VerifySelfSignature(csr));
        Assert.True(QertumKeyCodec.IsMatchingPair(reloaded, keys.Public));
        Assert.Equal(name, QertumKeyCodec.SignatureAlgorithmName(keys.Private));
        Assert.Equal(
            ((CompositePublicKey)keys.Public).GetEncoded(),
            ((CompositePublicKey)QertumKeyCodec.PublicKeyFromPrivate(keys.Private)).GetEncoded());
    }

    [Fact]
    public void CompositeKeysFromDifferentPairsDoNotMatch()
    {
        var algorithm = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!;
        var one = CompositeKeyPairGenerator.Generate(algorithm, Random);
        var other = CompositeKeyPairGenerator.Generate(algorithm, Random);

        Assert.False(QertumKeyCodec.IsMatchingPair(one.Private, other.Public));
    }

    [Fact]
    public void MalformedCompositePublicKeyIsNotSupported()
    {
        var algorithm = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!;
        var truncated = new SubjectPublicKeyInfo(new AlgorithmIdentifier(algorithm.Oid), new byte[100]);

        Assert.Throws<NotSupportedException>(() => QertumKeyCodec.PublicKeyOf(truncated));
    }

    // ---- parity with BouncyCastle for every algorithm Qertum issues today ----

    public static TheoryData<string> KemAlgorithms => ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

    // ML-KEM keys cannot sign, so they have no self-signed certificate, CSR or IsMatchingPair probe;
    // what the codec must still do for them is encode and decode exactly as BouncyCastle does.
    [Theory]
    [MemberData(nameof(KemAlgorithms))]
    public void KemKeysEncodeAndDecodeExactlyAsBouncyCastleDoes(string algorithm)
    {
        var keys = Generate(algorithm);

        Assert.Equal(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public).GetEncoded(),
            QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public).GetEncoded());
        Assert.Equal(
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(keys.Public),
            QertumKeyCodec.SubjectKeyIdentifierFor(keys.Public));
        Assert.Equal(keys.Public, QertumKeyCodec.PublicKeyOf(QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public)));

        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(keys.Private);
        Assert.Equal(writer.ToString(), QertumKeyCodec.WritePrivateKeyPem(keys.Private));
        Assert.Equal(
            PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private).GetEncoded(),
            QertumKeyCodec.ToPrivateKeyInfo(QertumKeyCodec.ReadPrivateKeyPem(writer.ToString())).GetEncoded());
    }

    [Theory]
    [MemberData(nameof(BouncyCastleAlgorithms))]
    public void SubjectPublicKeyInfoAndKeyIdentifierMatchBouncyCastle(string algorithm)
    {
        var keys = Generate(algorithm);

        Assert.Equal(
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keys.Public).GetEncoded(),
            QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public).GetEncoded());
        Assert.Equal(
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(keys.Public),
            QertumKeyCodec.SubjectKeyIdentifierFor(keys.Public));
    }

    [Theory]
    [MemberData(nameof(BouncyCastleAlgorithms))]
    public void PrivateKeyPemIsWhatPemWriterWrites(string algorithm)
    {
        var keys = Generate(algorithm);
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(keys.Private);

        Assert.Equal(writer.ToString(), QertumKeyCodec.WritePrivateKeyPem(keys.Private));
        Assert.True(QertumKeyCodec.IsMatchingPair(QertumKeyCodec.ReadPrivateKeyPem(writer.ToString()), keys.Public));
    }

    [Theory]
    [MemberData(nameof(BouncyCastleAlgorithms))]
    public void CertificateCsrAndResponderIdMatchBouncyCastle(string algorithm)
    {
        var keys = Generate(algorithm);
        var subject = new X509Name("CN=parity");
        var certificate = SelfSigned(keys, subject);
        var csr = new Pkcs10CertificationRequest(QertumKeyCodec.SignatureFactoryFor(keys.Private), subject, keys.Public, null);

        Assert.Equal(certificate.GetPublicKey(), QertumKeyCodec.PublicKeyOf(certificate));
        Assert.Equal(csr.GetPublicKey(), QertumKeyCodec.PublicKeyOf(csr));
        Assert.Equal(csr.Verify(), QertumKeyCodec.VerifySelfSignature(csr));
        Assert.Equal(new RespID(keys.Public), QertumKeyCodec.ResponderIdByKey(certificate));
        Assert.Equal(certificate, QertumKeyCodec.ReadCertificatePem(QertumKeyCodec.WriteCertificatePem(certificate)));
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECDSA-P256")]
    [InlineData("ML-DSA-65")]
    public void PublicKeyFromPrivateMatchesTheGeneratedPublicKey(string algorithm)
    {
        var keys = Generate(algorithm);

        Assert.Equal(keys.Public, QertumKeyCodec.PublicKeyFromPrivate(keys.Private));
    }

    [Fact]
    public void KeysOfDifferentTypesDoNotMatch() =>
        Assert.False(QertumKeyCodec.IsMatchingPair(Generate("ECDSA-P256").Private, Generate("RSA").Public));

    [Fact]
    public void PemWithoutACertificateReadsAsNull() =>
        Assert.Null(QertumKeyCodec.ReadCertificatePem("not a pem"));

    [Fact]
    public void PemWithoutAPrivateKeyIsRefused()
    {
        var certificatePem = QertumKeyCodec.WriteCertificatePem(SelfSigned(Generate("ECDSA-P256"), new X509Name("CN=x")));

        Assert.Throws<ArgumentException>(() => QertumKeyCodec.ReadPrivateKeyPem(certificatePem));
    }

    private static X509Certificate SelfSigned(AsymmetricCipherKeyPair keys, X509Name subject)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.One);
        generator.SetIssuerDN(subject);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public));
        return generator.Generate(QertumKeyCodec.SignatureFactoryFor(keys.Private));
    }

    private static AsymmetricCipherKeyPair Generate(string algorithm)
    {
        IAsymmetricCipherKeyPairGenerator generator;
        KeyGenerationParameters parameters;
        switch (algorithm)
        {
            case "RSA":
                (generator, parameters) = (new RsaKeyPairGenerator(), new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), Random, 2048, 100));
                break;
            case "ECDSA-P256":
                (generator, parameters) = (new ECKeyPairGenerator(), new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), Random));
                break;
            case "ML-DSA-65":
                (generator, parameters) = (new MLDsaKeyPairGenerator(), new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_65));
                break;
            case "SLH-DSA-SHA2-128F":
                (generator, parameters) = (new SlhDsaKeyPairGenerator(), new SlhDsaKeyGenerationParameters(Random, SlhDsaParameters.slh_dsa_sha2_128f));
                break;
            case "ML-KEM-512":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_512));
                break;
            case "ML-KEM-768":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_768));
                break;
            case "ML-KEM-1024":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_1024));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm));
        }

        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }

    private static CompositeTestVectors.Vector Vector(string name) =>
        CompositeTestVectors.For(CompositeAlgorithms.FindByName(name)!);
}
