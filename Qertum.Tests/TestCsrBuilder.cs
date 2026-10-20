using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Qertum.Services.Acme;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests;

/// <summary>Shared CSR factory for tests. Modeled on the plain <see cref="Pkcs10CertificationRequest"/>
/// construction in <c>CertificateGeneratorTests.DetectAlgorithmFromCsr_ReturnsMlDsa65ForMlDsaCsr</c>,
/// extended with a <c>pkcs9_at_extensionRequest</c> attribute carrying a SubjectAlternativeName
/// extension so tests can exercise SAN-aware CSR parsing without duplicating this construction.
///
/// The key-pair overloads exist because ACME and EST detect the issuance algorithm from the CSR's
/// public key, so tests need CSRs whose keys are ML-DSA and — for the rejection paths — key types
/// Qertum has no <see cref="CertificateKeyAlgorithm"/> for at all.</summary>
internal static class TestCsrBuilder
{
    public static string BuildBase64Url(string subjectCn, IReadOnlyList<string> sanDnsNames) =>
        BuildBase64Url(subjectCn, sanDnsNames, GenerateRsa(), "SHA256WITHRSA");

    public static string BuildBase64Url(
        string subjectCn,
        IReadOnlyList<string> sanDnsNames,
        AsymmetricCipherKeyPair keyPair,
        string signatureAlgorithm)
    {
        var csr = new Pkcs10CertificationRequest(
            signatureAlgorithm, new X509Name($"CN={subjectCn}"), keyPair.Public, SanAttributes(sanDnsNames), keyPair.Private);

        return JwkConverter.Base64UrlEncode(csr.GetDerEncoded());
    }

    /// <summary>
    /// A composite ML-DSA CSR (draft-ietf-lamps-pq-composite-sigs-19), signed through
    /// <see cref="QertumKeyCodec"/> because BouncyCastle's own PKCS#10 path cannot sign with a
    /// composite key.
    /// </summary>
    public static string BuildCompositeBase64Url(string subjectCn, IReadOnlyList<string> sanDnsNames, string algorithmName)
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName(algorithmName)!, new SecureRandom());
        var csr = new Pkcs10CertificationRequest(
            QertumKeyCodec.SignatureFactoryFor(keys.Private),
            new X509Name($"CN={subjectCn}"),
            QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public),
            SanAttributes(sanDnsNames));

        return JwkConverter.Base64UrlEncode(csr.GetDerEncoded());
    }

    private static Asn1Set? SanAttributes(IReadOnlyList<string> sanDnsNames)
    {
        if (sanDnsNames.Count == 0)
            return null;

        var names = sanDnsNames.Select(n => new GeneralName(GeneralName.DnsName, n)).ToArray();
        var sanExtension = new X509Extensions(new Dictionary<DerObjectIdentifier, X509Extension>
        {
            { X509Extensions.SubjectAlternativeName, new X509Extension(false, new DerOctetString(new GeneralNames(names))) }
        });
        return new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(sanExtension)));
    }

    /// <summary>An ML-DSA-65 CSR — a PQC algorithm Qertum supports.</summary>
    public static string BuildMlDsaBase64Url(string subjectCn, IReadOnlyList<string> sanDnsNames, bool level5 = false) =>
        BuildBase64Url(subjectCn, sanDnsNames,
            GenerateMlDsa(level5 ? MLDsaParameters.ml_dsa_87 : MLDsaParameters.ml_dsa_65),
            level5 ? "ML-DSA-87" : "ML-DSA-65");

    /// <summary>An ML-DSA-44 CSR. RFC 9881 standardizes this level, but Qertum has no
    /// <c>CertificateKeyAlgorithm</c> for it, so detection must refuse rather than guess.</summary>
    public static string BuildMlDsa44Base64Url(string subjectCn) =>
        BuildBase64Url(subjectCn, [], GenerateMlDsa(MLDsaParameters.ml_dsa_44), "ML-DSA-44");

    /// <summary>An Ed25519 CSR — a key type Qertum cannot issue for at all.</summary>
    public static string BuildEd25519Base64Url(string subjectCn)
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return BuildBase64Url(subjectCn, [], gen.GenerateKeyPair(), "Ed25519");
    }

    /// <summary>
    /// A CSR naming an ML-KEM-768 public key. A KEM key cannot sign, so no genuine CSR for one can
    /// exist; this one is signed by an unrelated ECDSA key, which is the closest a client can get and
    /// exactly what the self-signature check must refuse.
    /// </summary>
    public static string BuildMlKemKeyedBase64Url(string subjectCn)
    {
        var random = new SecureRandom();
        var kem = new MLKemKeyPairGenerator();
        kem.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        var ec = new ECKeyPairGenerator();
        ec.Init(new ECKeyGenerationParameters(Org.BouncyCastle.Asn1.Sec.SecObjectIdentifiers.SecP256r1, random));
        var csr = new Pkcs10CertificationRequest(
            QertumKeyCodec.SignatureFactoryFor(ec.GenerateKeyPair().Private), new X509Name($"CN={subjectCn}"),
            kem.GenerateKeyPair().Public, null);
        return JwkConverter.Base64UrlEncode(csr.GetDerEncoded());
    }

    /// <summary>An ECDSA CSR on the named curve (<c>P-256</c> or <c>P-384</c>).</summary>
    public static string BuildEcdsaBase64Url(string subjectCn, string curveName)
    {
        var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(curveName)!;
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(
            new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H), new SecureRandom()));
        return BuildBase64Url(subjectCn, [], gen.GenerateKeyPair(),
            curveName == "P-384" ? "SHA384WITHECDSA" : "SHA256WITHECDSA");
    }

    private static AsymmetricCipherKeyPair GenerateRsa()
    {
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        return keyGen.GenerateKeyPair();
    }

    private static AsymmetricCipherKeyPair GenerateMlDsa(MLDsaParameters parameters)
    {
        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), parameters));
        return gen.GenerateKeyPair();
    }
}
