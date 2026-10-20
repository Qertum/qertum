using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// Composite keys inside the X.509 structures a CA produces: a freshly generated key signs a
/// certificate, a CSR, a CRL and an OCSP response through BouncyCastle's own builders, and each
/// verifies through the composite verifier. The algorithm identifier must be the composite OID with
/// parameters absent (draft -19 §5).
/// </summary>
public sealed class CompositeX509Tests
{
    private static readonly SecureRandom Random = new();
    private static readonly X509Name Name = new("CN=Composite Test");

    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    [Theory]
    [MemberData(nameof(Names))]
    public void GeneratedKeyPairIsFreshAndConsistent(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;

        var first = CompositeKeyPairGenerator.Generate(algorithm, Random);
        var second = CompositeKeyPairGenerator.Generate(algorithm, Random);

        var firstPrivate = Assert.IsType<CompositePrivateKey>(first.Private);
        var firstPublic = Assert.IsType<CompositePublicKey>(first.Public);
        Assert.Equal(firstPrivate.PublicKey.GetEncoded(), firstPublic.GetEncoded());
        // §3.1: both components are generated fresh every time.
        Assert.NotEqual(firstPublic.GetEncoded(), ((CompositePublicKey)second.Public).GetEncoded());
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void SelfSignedCertificateVerifiesAndCarriesTheCompositeIdentifier(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var keys = CompositeKeyPairGenerator.Generate(algorithm, Random);

        var certificate = SelfSigned(keys);

        certificate.Verify(new CompositeVerifierProvider((CompositePublicKey)keys.Public));
        Assert.Equal(algorithm.Oid.Id, certificate.SigAlgOid);
        Assert.Null(certificate.CertificateStructure.SignatureAlgorithm.Parameters);
        Assert.Equal(algorithm.Oid, certificate.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm);
        Assert.Null(certificate.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Parameters);
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void PublishedCertificateVerifies(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var vector = CompositeTestVectors.For(algorithm);
        var certificate = new X509CertificateParser().ReadCertificate(vector.Certificate);

        certificate.Verify(new CompositeVerifierProvider(CompositePublicKey.Decode(algorithm, vector.PublicKey)));
    }

    [Fact]
    public void CertificateSignedByAnotherKeyDoesNotVerify()
    {
        var algorithm = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!;
        var certificate = SelfSigned(CompositeKeyPairGenerator.Generate(algorithm, Random));
        var stranger = (CompositePublicKey)CompositeKeyPairGenerator.Generate(algorithm, Random).Public;

        Assert.ThrowsAny<Exception>(() => certificate.Verify(new CompositeVerifierProvider(stranger)));
    }

    [Fact]
    public void SignatureUnderAnotherCompositeOidDoesNotVerify()
    {
        // Same ML-DSA level and curve family, different combination: the OID in the signed
        // structure must match the key's own composite OID.
        var signedWith = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!, Random);
        var certificate = SelfSigned(signedWith);
        var otherAlgorithmKey = (CompositePublicKey)CompositeKeyPairGenerator
            .Generate(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P384-SHA512")!, Random).Public;

        Assert.ThrowsAny<Exception>(() => certificate.Verify(new CompositeVerifierProvider(otherAlgorithmKey)));
    }

    [Theory]
    [InlineData("MLDSA65-ECDSA-P256-SHA512")]
    [InlineData("MLDSA65-RSA3072-PSS-SHA512")]
    [InlineData("MLDSA87-Ed448-SHAKE256")]
    public void CsrSignedWithACompositeKeyVerifies(string name)
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName(name)!, Random);
        var publicKey = (CompositePublicKey)keys.Public;

        var csr = new Pkcs10CertificationRequest(
            new CompositeSignatureFactory((CompositePrivateKey)keys.Private), Name, Spki(publicKey), null);

        Assert.True(csr.Verify(new CompositeVerifierProvider(publicKey)));
    }

    [Theory]
    [InlineData("MLDSA65-ECDSA-P256-SHA512")]
    [InlineData("MLDSA87-ECDSA-P384-SHA512")]
    public void CrlSignedWithACompositeKeyVerifies(string name)
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName(name)!, Random);
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(Name);
        generator.SetThisUpdate(DateTime.UtcNow);
        generator.SetNextUpdate(DateTime.UtcNow.AddDays(1));

        var crl = generator.Generate(new CompositeSignatureFactory((CompositePrivateKey)keys.Private));

        crl.Verify(new CompositeVerifierProvider((CompositePublicKey)keys.Public));
    }

    [Theory]
    [InlineData("MLDSA65-ECDSA-P256-SHA512")]
    [InlineData("MLDSA87-ECDSA-P384-SHA512")]
    public void OcspResponseSignedWithACompositeKeyVerifies(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var keys = CompositeKeyPairGenerator.Generate(algorithm, Random);
        var issuer = SelfSigned(keys);
        var keyHash = DigestUtilities.CalculateDigest("SHA-1",
            issuer.CertificateStructure.SubjectPublicKeyInfo.PublicKey.GetBytes());
        var generator = new BasicOcspRespGenerator(new RespID(new ResponderID(new DerOctetString(keyHash))));
        generator.AddResponse(new CertificateID(CertificateID.DigestSha1, issuer, BigInteger.Two), CertificateStatus.Good);

        var response = generator.Generate(new CompositeSignatureFactory((CompositePrivateKey)keys.Private), [issuer], DateTime.UtcNow);

        // BasicOcspResp.Verify only takes a key BouncyCastle knows, so check the signature directly.
        var verifier = new CompositeVerifierProvider((CompositePublicKey)keys.Public)
            .CreateVerifierFactory(new AlgorithmIdentifier(algorithm.Oid)).CreateCalculator();
        var tbs = response.GetTbsResponseData();
        using (var stream = verifier.Stream)
            stream.Write(tbs, 0, tbs.Length);
        Assert.True(verifier.GetResult().IsVerified(response.GetSignature()));
        Assert.Equal(algorithm.Oid, BasicOcspResponse.GetInstance(response.GetEncoded()).SignatureAlgorithm.Algorithm);
    }

    private static X509Certificate SelfSigned(AsymmetricCipherKeyPair keys)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.One);
        generator.SetIssuerDN(Name);
        generator.SetSubjectDN(Name);
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetSubjectPublicKeyInfo(Spki((CompositePublicKey)keys.Public));
        return generator.Generate(new CompositeSignatureFactory((CompositePrivateKey)keys.Private));
    }

    private static SubjectPublicKeyInfo Spki(CompositePublicKey key) =>
        new(new AlgorithmIdentifier(key.Algorithm.Oid), key.GetEncoded());
}
