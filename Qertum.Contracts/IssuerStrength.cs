using System.Text.Json.Serialization;
namespace Qertum.Services;

/// <summary>
/// What the CA does when a certificate's key claims a higher NIST post-quantum security level than the
/// key of the CA that signs it (<see cref="IssuerStrength"/>). Stored and serialized as the name.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuerStrengthMode
{
    /// <summary>The comparison is not made.</summary>
    Off,

    /// <summary>The request is allowed and carries a warning naming both levels.</summary>
    Warn,

    /// <summary>The request is refused as a policy violation.</summary>
    Enforce
}

/// <summary>
/// NIST security levels of the post-quantum algorithms, and the one comparison the issuer-strength rule
/// makes: a subject must not claim more strength than its issuer can back.
/// </summary>
public static class IssuerStrength
{
    /// <summary>
    /// The NIST security category (1, 2, 3 or 5) of the post-quantum part of <paramref name="algorithm"/>:
    /// the ML-DSA, SLH-DSA or ML-KEM parameter set, the ML-DSA half of a composite or hybrid, and the signing
    /// half of a signing + encryption pair. Null for RSA and ECDSA, which have no post-quantum level.
    /// </summary>
    public static int? NistLevel(CertificateKeyAlgorithm algorithm) => algorithm switch
    {
        CertificateKeyAlgorithm.SlhDsaSha2128s or CertificateKeyAlgorithm.SlhDsaSha2128f
            or CertificateKeyAlgorithm.MlKem512 => 1,
        CertificateKeyAlgorithm.MlDsa44 or CertificateKeyAlgorithm.PairMlDsa44MlKem512
            or CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256 or CertificateKeyAlgorithm.MlDsa44Rsa2048Pkcs15Sha256
            or CertificateKeyAlgorithm.MlDsa44Ed25519Sha512 or CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256 => 2,
        CertificateKeyAlgorithm.MlDsa65 or CertificateKeyAlgorithm.HybridEcdsaP256 or CertificateKeyAlgorithm.PairMlDsa65MlKem768
            or CertificateKeyAlgorithm.MlKem768 or CertificateKeyAlgorithm.SlhDsaSha2192s or CertificateKeyAlgorithm.SlhDsaSha2192f
            or CertificateKeyAlgorithm.MlDsa65Rsa3072PssSha512 or CertificateKeyAlgorithm.MlDsa65Rsa3072Pkcs15Sha512
            or CertificateKeyAlgorithm.MlDsa65Rsa4096PssSha512 or CertificateKeyAlgorithm.MlDsa65Rsa4096Pkcs15Sha512
            or CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512 or CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512
            or CertificateKeyAlgorithm.MlDsa65EcdsaBrainpoolP256r1Sha512 or CertificateKeyAlgorithm.MlDsa65Ed25519Sha512 => 3,
        CertificateKeyAlgorithm.MlDsa87 or CertificateKeyAlgorithm.HybridEcdsaP384 or CertificateKeyAlgorithm.PairMlDsa87MlKem1024
            or CertificateKeyAlgorithm.MlKem1024 or CertificateKeyAlgorithm.SlhDsaSha2256s or CertificateKeyAlgorithm.SlhDsaSha2256f
            or CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512 or CertificateKeyAlgorithm.MlDsa87EcdsaBrainpoolP384r1Sha512
            or CertificateKeyAlgorithm.MlDsa87Ed448Shake256 or CertificateKeyAlgorithm.MlDsa87Rsa3072PssSha512
            or CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512 or CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512 => 5,
        _ => null
    };

    /// <summary>
    /// The refusal or warning text when a <paramref name="subject"/> key claims a higher level than the
    /// <paramref name="issuer"/> key, or null when the comparison does not apply. A classical issuer is
    /// exempt (the P-384 root to ML-DSA-87 migration path would break otherwise), and so is a classical
    /// subject or an issuer whose algorithm is unknown.
    /// </summary>
    public static string? Mismatch(CertificateKeyAlgorithm subject, CertificateKeyAlgorithm? issuer, string issuerName)
    {
        if (issuer is not { } issuerAlgorithm) return null;
        if (NistLevel(issuerAlgorithm) is not { } issuerLevel || NistLevel(subject) is not { } subjectLevel) return null;
        return subjectLevel > issuerLevel
            ? $"{subject.ToCanonicalString()} claims NIST level {subjectLevel}, but issuer '{issuerName}' " +
              $"({issuerAlgorithm.ToCanonicalString()}) only backs level {issuerLevel}."
            : null;
    }
}
