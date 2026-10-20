using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.Services.Crypto.Composite;
using PemObject = Org.BouncyCastle.Utilities.IO.Pem.PemObject;
using RawPemReader = Org.BouncyCastle.Utilities.IO.Pem.PemReader;
using RawPemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;

namespace Qertum.Services.Crypto;

/// <summary>
/// The only code that turns bytes into keys and keys into bytes. Composite ML-DSA OIDs are handled
/// here, because BouncyCastle's factories (PublicKeyFactory, PemReader, X509Certificate.GetPublicKey,
/// Pkcs10CertificationRequest.Verify) cannot be extended and throw on them; every other algorithm is
/// passed to BouncyCastle exactly as before. <c>KeyCodecUsageTests</c> fails the build when production
/// code bypasses this class.
/// </summary>
public static class QertumKeyCodec
{
    private const string Pkcs8PemType = "PRIVATE KEY";

    public static AsymmetricKeyParameter PublicKeyOf(SubjectPublicKeyInfo subjectPublicKeyInfo)
    {
        if (CompositeAlgorithms.FindByOid(subjectPublicKeyInfo.Algorithm.Algorithm) is not { } composite)
            return PublicKeyFactory.CreateKey(subjectPublicKeyInfo);

        if (subjectPublicKeyInfo.Algorithm.Parameters is not null)
            throw new NotSupportedException($"A {composite.Name} key must not carry algorithm parameters.");
        try
        {
            return CompositePublicKey.Decode(composite, subjectPublicKeyInfo.PublicKey.GetBytes());
        }
        catch (ArgumentException ex)
        {
            throw new NotSupportedException(ex.Message, ex);
        }
    }

    public static AsymmetricKeyParameter PublicKeyOf(X509Certificate certificate) =>
        PublicKeyOf(certificate.CertificateStructure.SubjectPublicKeyInfo);

    public static AsymmetricKeyParameter PublicKeyOf(Pkcs10CertificationRequest csr) =>
        PublicKeyOf(csr.GetCertificationRequestInfo().SubjectPublicKeyInfo);

    public static SubjectPublicKeyInfo ToSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) =>
        publicKey is CompositePublicKey composite
            ? new SubjectPublicKeyInfo(new AlgorithmIdentifier(composite.Algorithm.Oid), composite.GetEncoded())
            : SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

    public static SubjectKeyIdentifier SubjectKeyIdentifierFor(AsymmetricKeyParameter publicKey) =>
        X509ExtensionUtilities.CreateSubjectKeyIdentifier(ToSubjectPublicKeyInfo(publicKey));

    /// <summary>
    /// The AuthorityKeyIdentifier for certificates and CRLs this issuer signs. BouncyCastle takes it
    /// from the issuer's SubjectKeyIdentifier extension, and only falls back to parsing the key when
    /// the extension is missing — which it cannot do for a composite key, so that one case is built
    /// from the issuer's SPKI instead. Every other issuer gets exactly what BouncyCastle produces.
    /// </summary>
    public static AuthorityKeyIdentifier AuthorityKeyIdentifierFor(X509Certificate issuer) =>
        issuer.GetExtensionValue(X509Extensions.SubjectKeyIdentifier) is null
        && CompositeAlgorithms.FindByOid(issuer.CertificateStructure.SubjectPublicKeyInfo.Algorithm.Algorithm) is not null
            ? X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuer.CertificateStructure.SubjectPublicKeyInfo)
            : X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuer);

    /// <summary>
    /// True when an X.509 algorithm identifier (a key's or a signature's) is a composite ML-DSA one.
    /// For code holding .NET certificates, which report these as bare OIDs.
    /// </summary>
    public static bool IsCompositeOid(string? oid) =>
        oid is not null && CompositeAlgorithms.FindByOid(new DerObjectIdentifier(oid)) is not null;

    public static AsymmetricKeyParameter PublicKeyFromPrivate(AsymmetricKeyParameter privateKey) => privateKey switch
    {
        CompositePrivateKey composite => composite.PublicKey,
        MLDsaPrivateKeyParameters mlDsa => mlDsa.GetPublicKey(),
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters(ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        _ => throw new NotSupportedException($"Unsupported key type: {privateKey.GetType().Name}")
    };

    /// <summary>The signature algorithm a CA holding this private key signs under.</summary>
    public static string SignatureAlgorithmName(AsymmetricKeyParameter privateKey) =>
        privateKey is CompositePrivateKey composite
            ? composite.Algorithm.Name
            : AlgorithmStrategyFactory.CreateFromPrivateKey(privateKey).CaSignatureAlgorithm;

    public static ISignatureFactory SignatureFactoryFor(AsymmetricKeyParameter privateKey, SecureRandom? random = null) =>
        privateKey is CompositePrivateKey composite
            ? new CompositeSignatureFactory(composite, random)
            : new Asn1SignatureFactory(SignatureAlgorithmName(privateKey), privateKey, random ?? new SecureRandom());

    public static IVerifierFactoryProvider VerifierFor(AsymmetricKeyParameter publicKey) =>
        publicKey is CompositePublicKey composite
            ? new CompositeVerifierProvider(composite)
            : new Asn1VerifierFactoryProvider(publicKey);

    /// <summary>A CSR's self-signature (proof of possession), checked with the key it carries.</summary>
    public static bool VerifySelfSignature(Pkcs10CertificationRequest csr) =>
        csr.Verify(VerifierFor(PublicKeyOf(csr)));

    /// <summary>True when data signed with <paramref name="privateKey"/> verifies under <paramref name="publicKey"/>.</summary>
    public static bool IsMatchingPair(AsymmetricKeyParameter privateKey, AsymmetricKeyParameter publicKey)
    {
        byte[] probe = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        try
        {
            var factory = SignatureFactoryFor(privateKey);
            var signer = factory.CreateCalculator();
            using (var stream = signer.Stream)
                stream.Write(probe);
            var signature = signer.GetResult().Collect();

            var verifier = VerifierFor(publicKey).CreateVerifierFactory(factory.AlgorithmDetails).CreateCalculator();
            using (var stream = verifier.Stream)
                stream.Write(probe);
            return verifier.GetResult().IsVerified(signature);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A key that cannot even drive the other half's algorithm is, by definition, not its pair.
            return false;
        }
    }

    /// <summary>
    /// The OCSP ResponderID "byKey" (RFC 6960 §4.2.2.3): SHA-1 of the responder's subjectPublicKey,
    /// read from its certificate so no key object is needed.
    /// </summary>
    public static RespID ResponderIdByKey(X509Certificate responderCertificate) =>
        new(new ResponderID(new DerOctetString(DigestUtilities.CalculateDigest("SHA-1",
            responderCertificate.CertificateStructure.SubjectPublicKeyInfo.PublicKey.GetBytes()))));

    /// <summary>The certificate in <paramref name="pem"/>, or null when it holds none.</summary>
    public static X509Certificate? ReadCertificatePem(string pem)
    {
        using var reader = new StringReader(pem);
        return new PemReader(reader).ReadObject() as X509Certificate;
    }

    public static string WriteCertificatePem(X509Certificate certificate) => WriteOpenSslPem(certificate);

    /// <summary>
    /// Reads a private key. A composite key is PKCS#8 under its composite OID (§5.3); everything else
    /// is read by BouncyCastle's OpenSSL reader, as before.
    /// </summary>
    public static AsymmetricKeyParameter ReadPrivateKeyPem(string pem)
    {
        using (var reader = new StringReader(pem))
        {
            if (new RawPemReader(reader).ReadPemObject() is { Type: Pkcs8PemType } pemObject)
            {
                var info = PrivateKeyInfo.GetInstance(pemObject.Content);
                if (CompositeAlgorithms.FindByOid(info.PrivateKeyAlgorithm.Algorithm) is { } composite)
                {
                    try
                    {
                        return CompositePrivateKey.Decode(composite, info.PrivateKey.GetOctets());
                    }
                    catch (ArgumentException ex)
                    {
                        throw new NotSupportedException(ex.Message, ex);
                    }
                }
            }
        }

        using var openSsl = new StringReader(pem);
        return new PemReader(openSsl).ReadObject() switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter { IsPrivate: true } key => key,
            _ => throw new ArgumentException("The PEM does not hold a private key.", nameof(pem))
        };
    }

    public static string WritePrivateKeyPem(AsymmetricKeyParameter privateKey)
    {
        if (privateKey is not CompositePrivateKey composite)
            return WriteOpenSslPem(privateKey);

        using var writer = new StringWriter();
        new RawPemWriter(writer).WriteObject(new PemObject(Pkcs8PemType, CompositePkcs8(composite)));
        return writer.ToString();
    }

    private const string EncryptedPkcs8PemType = "ENCRYPTED PRIVATE KEY";
    private const string CsrPemType = "CERTIFICATE REQUEST";

    /// <summary>
    /// PKCS#8 EncryptedPrivateKeyInfo, PBES2 (PBKDF2-HMAC-SHA-256, AES-256-CBC, <see cref="Pkcs12Writer.Iterations"/>
    /// iterations) — the protection <see cref="Pkcs12Writer"/> gives a PKCS#12 key bag, so OpenSSL 3 reads it
    /// (<c>openssl pkey -passin</c>). Composite keys are wrapped in their own §5.3 PrivateKeyInfo.
    /// </summary>
    public static string WriteEncryptedPrivateKeyPem(AsymmetricKeyParameter privateKey, string passphrase)
    {
        var random = new SecureRandom();
        var salt = new byte[16];
        random.NextBytes(salt);
        var encrypted = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256,
            passphrase.ToCharArray(), salt, Pkcs12Writer.Iterations, random, ToPrivateKeyInfo(privateKey));
        using var writer = new StringWriter();
        new RawPemWriter(writer).WriteObject(new PemObject(EncryptedPkcs8PemType, encrypted.GetEncoded()));
        return writer.ToString();
    }

    public static AsymmetricKeyParameter ReadEncryptedPrivateKeyPem(string pem, string passphrase)
    {
        using var reader = new StringReader(pem);
        var pemObject = new RawPemReader(reader).ReadPemObject();
        if (pemObject is not { Type: EncryptedPkcs8PemType })
            throw new ArgumentException("The file does not hold an encrypted PKCS#8 private key.", nameof(pem));

        PrivateKeyInfo info;
        try
        {
            info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(passphrase.ToCharArray(),
                EncryptedPrivateKeyInfo.GetInstance(pemObject.Content));
        }
        catch (Exception ex) when (ex is InvalidCipherTextException or CryptoException or ArgumentException or InvalidOperationException)
        {
            throw new ArgumentException("The passphrase is wrong or the key file is damaged.", nameof(passphrase), ex);
        }

        if (CompositeAlgorithms.FindByOid(info.PrivateKeyAlgorithm.Algorithm) is { } composite)
            return CompositePrivateKey.Decode(composite, info.PrivateKey.GetOctets());
        return PrivateKeyFactory.CreateKey(info);
    }

    public static string WriteCertificationRequestPem(Pkcs10CertificationRequest csr)
    {
        using var writer = new StringWriter();
        new RawPemWriter(writer).WriteObject(new PemObject(CsrPemType, csr.GetDerEncoded()));
        return writer.ToString();
    }

    public static Pkcs10CertificationRequest ReadCertificationRequestPem(string pem)
    {
        using var reader = new StringReader(pem);
        var pemObject = new RawPemReader(reader).ReadPemObject();
        return pemObject is { Type: CsrPemType or "NEW CERTIFICATE REQUEST" }
            ? new Pkcs10CertificationRequest(pemObject.Content)
            : throw new ArgumentException("The PEM does not hold a certificate request.", nameof(pem));
    }

    /// <summary>The PKCS#8 <c>PrivateKeyInfo</c> of a private key, composite (§5.3) or not.</summary>
    public static PrivateKeyInfo ToPrivateKeyInfo(AsymmetricKeyParameter privateKey) =>
        privateKey is CompositePrivateKey composite
            // Parsed from our own DER: PrivateKeyInfo's constructor would wrap the octets a second time.
            ? PrivateKeyInfo.GetInstance(CompositePkcs8(composite))
            : PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

    /// <summary>
    /// A password-protected PKCS#12 file holding the certificate, its private key and the chain, for
    /// every algorithm Qertum issues. See <see cref="Pkcs12Writer"/> for the protection it uses.
    /// </summary>
    /// <param name="password">The export password; null or empty gives a file protected by the empty password.</param>
    public static byte[] ExportPkcs12(string certificatePem, string privateKeyPem, IReadOnlyList<string> chainPems,
        string? password, string friendlyName)
    {
        var certificate = ReadCertificatePem(certificatePem)
            ?? throw new ArgumentException("The certificate PEM holds no certificate.", nameof(certificatePem));
        var chain = chainPems
            .Select(pem => ReadCertificatePem(pem) ?? throw new ArgumentException("A chain PEM holds no certificate.", nameof(chainPems)))
            .ToList();

        return Pkcs12Writer.Write(certificate, ToPrivateKeyInfo(ReadPrivateKeyPem(privateKeyPem)), chain,
            password ?? string.Empty, friendlyName, new SecureRandom());
    }

    /// <summary>OneAsymmetricKey v0 whose privateKey octets are the §4.2 serialization, not re-wrapped.</summary>
    private static byte[] CompositePkcs8(CompositePrivateKey composite) =>
        new DerSequence(
            DerInteger.ValueOf(0),
            new AlgorithmIdentifier(composite.Algorithm.Oid),
            new DerOctetString(composite.GetEncoded())).GetEncoded(Asn1Encodable.Der);

    private static string WriteOpenSslPem(object value)
    {
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(value);
        return writer.ToString();
    }
}
