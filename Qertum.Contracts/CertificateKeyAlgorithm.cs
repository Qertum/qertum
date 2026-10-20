using System.Text.Json;
using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Key and signature algorithm used for a certificate or CA.</summary>
[JsonConverter(typeof(CertificateKeyAlgorithmJsonConverter))]
public enum CertificateKeyAlgorithm
{
    /// <summary>RSA 2048-bit leaf key (4096-bit for CA keys). Broadest client compatibility.</summary>
    Rsa,

    /// <summary>ECDSA with NIST P-256. Compact signatures, widely supported.</summary>
    EcdsaP256,

    /// <summary>ECDSA with NIST P-384. Higher security margin than P-256.</summary>
    EcdsaP384,

    /// <summary>ML-DSA-65 (Dilithium3). FIPS 204 post-quantum, security level 3. ~1.9 KB public key.</summary>
    MlDsa65,

    /// <summary>ML-DSA-87 (Dilithium5). FIPS 204 post-quantum, security level 5. ~2.6 KB public key.</summary>
    MlDsa87,

    /// <summary>Hybrid paired issuance: ECDSA P-256 + ML-DSA-65. Issues two certificates from one request.</summary>
    HybridEcdsaP256,

    /// <summary>Hybrid paired issuance: ECDSA P-384 + ML-DSA-87. Issues two certificates from one request.</summary>
    HybridEcdsaP384,

    /// <summary>
    /// ML-DSA-44 (Dilithium2). FIPS 204 post-quantum, security level 2 — the smallest parameter
    /// set, with correspondingly smaller keys and signatures than ML-DSA-65.
    /// Declared last so the existing members keep their ordinal values.
    /// </summary>
    MlDsa44,

    /// <summary>
    /// SLH-DSA-SHA2-128S (FIPS 205). Stateless hash-based signature, security level 1, "small"
    /// variant: ~8 KB certificates and slow signing (hundreds of ms), with a 32-byte public key.
    /// </summary>
    SlhDsaSha2128s,

    /// <summary>
    /// SLH-DSA-SHA2-128F (FIPS 205). The "fast" variant of the same security level: signing is
    /// roughly 20x quicker than 128s, at about double the signature size.
    /// </summary>
    SlhDsaSha2128f,

    // Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-19 §6), in OID order
    // (1.3.6.1.5.5.7.6.37-.54). Appended after every existing member so no ordinal moves.

    /// <summary>Composite ML-DSA <c>MLDSA44-RSA2048-PSS-SHA256</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa44Rsa2048PssSha256,

    /// <summary>Composite ML-DSA <c>MLDSA44-RSA2048-PKCS15-SHA256</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa44Rsa2048Pkcs15Sha256,

    /// <summary>Composite ML-DSA <c>MLDSA44-Ed25519-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa44Ed25519Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA44-ECDSA-P256-SHA256</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa44EcdsaP256Sha256,

    /// <summary>Composite ML-DSA <c>MLDSA65-RSA3072-PSS-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65Rsa3072PssSha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-RSA3072-PKCS15-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65Rsa3072Pkcs15Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-RSA4096-PSS-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65Rsa4096PssSha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-RSA4096-PKCS15-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65Rsa4096Pkcs15Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-ECDSA-P256-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65EcdsaP256Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-ECDSA-P384-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65EcdsaP384Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-ECDSA-brainpoolP256r1-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65EcdsaBrainpoolP256r1Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA65-Ed25519-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa65Ed25519Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA87-ECDSA-P384-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87EcdsaP384Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA87-ECDSA-brainpoolP384r1-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87EcdsaBrainpoolP384r1Sha512,

    /// <summary>Composite ML-DSA <c>MLDSA87-Ed448-SHAKE256</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87Ed448Shake256,

    /// <summary>Composite ML-DSA <c>MLDSA87-RSA3072-PSS-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87Rsa3072PssSha512,

    /// <summary>Composite ML-DSA <c>MLDSA87-RSA4096-PSS-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87Rsa4096PssSha512,

    /// <summary>Composite ML-DSA <c>MLDSA87-ECDSA-P521-SHA512</c> (draft-ietf-lamps-pq-composite-sigs-19): one certificate whose ML-DSA and classical signatures must both verify.</summary>
    MlDsa87EcdsaP521Sha512,

    // ML-KEM (FIPS 203) key encapsulation. Appended after every existing member so no ordinal
    // moves. A KEM key can never sign: it is a subject key only, never an issuer.

    /// <summary>ML-KEM-512 (FIPS 203, security category 1). Encryption-only subject key.</summary>
    MlKem512,

    /// <summary>ML-KEM-768 (FIPS 203, security category 3). Encryption-only subject key.</summary>
    MlKem768,

    /// <summary>ML-KEM-1024 (FIPS 203, security category 5). Encryption-only subject key.</summary>
    MlKem1024,

    // Paired post-quantum signing + encryption issuance: one request, two certificates (an ML-DSA
    // signing certificate and an ML-KEM encryption certificate). Appended after every existing member
    // so no ordinal moves.

    /// <summary>Paired issuance: an ML-DSA-44 signing certificate and an ML-KEM-512 encryption certificate from one request.</summary>
    PairMlDsa44MlKem512,

    /// <summary>Paired issuance: an ML-DSA-65 signing certificate and an ML-KEM-768 encryption certificate from one request.</summary>
    PairMlDsa65MlKem768,

    /// <summary>Paired issuance: an ML-DSA-87 signing certificate and an ML-KEM-1024 encryption certificate from one request.</summary>
    PairMlDsa87MlKem1024
}

/// <summary>Broad classification of a <see cref="CertificateKeyAlgorithm"/> value.</summary>
public enum AlgorithmFamily
{
    /// <summary>RSA key-exchange and signature.</summary>
    Rsa,

    /// <summary>Elliptic-curve digital signature algorithm (classical).</summary>
    Ecdsa,

    /// <summary>NIST-standardized post-quantum signature algorithm (ML-DSA / FIPS 204).</summary>
    Pqc,

    /// <summary>Paired classical + PQC issuance that produces two certificates from a single request.</summary>
    Hybrid,

    /// <summary>
    /// Composite ML-DSA: one certificate carrying an ML-DSA key and a classical key under a single
    /// OID, whose signature is valid only if both component signatures verify.
    /// </summary>
    Composite,

    /// <summary>
    /// NIST-standardized post-quantum key encapsulation (ML-KEM / FIPS 203). Encryption-only: a
    /// KEM key cannot sign, so it is never an issuer and never carries a signature key usage.
    /// </summary>
    Kem,

    /// <summary>
    /// Paired post-quantum issuance: an ML-DSA signing certificate and an ML-KEM encryption certificate
    /// from one request. Neither certificate is classical; the pair can never be a CA key because one
    /// of its keys cannot sign.
    /// </summary>
    Pair
}

/// <summary>Extension methods for <see cref="CertificateKeyAlgorithm"/>.</summary>
public static class CertificateKeyAlgorithmExtensions
{
    /// <summary>
    /// The composite ML-DSA algorithms by their IANA OID (draft-ietf-lamps-pq-composite-sigs-19 §6),
    /// for display code that reads an OID off a certificate. Contracts cannot reference the
    /// BouncyCastle-based registry in <c>Qertum.Services</c>, so this is its string-only mirror;
    /// <c>CompositeAlgorithmsTests</c> pins the two together.
    /// </summary>
    public static IReadOnlyDictionary<string, CertificateKeyAlgorithm> CompositeAlgorithmsByOid { get; } =
        new Dictionary<string, CertificateKeyAlgorithm>(StringComparer.Ordinal)
        {
            ["1.3.6.1.5.5.7.6.37"] = CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256,
            ["1.3.6.1.5.5.7.6.38"] = CertificateKeyAlgorithm.MlDsa44Rsa2048Pkcs15Sha256,
            ["1.3.6.1.5.5.7.6.39"] = CertificateKeyAlgorithm.MlDsa44Ed25519Sha512,
            ["1.3.6.1.5.5.7.6.40"] = CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256,
            ["1.3.6.1.5.5.7.6.41"] = CertificateKeyAlgorithm.MlDsa65Rsa3072PssSha512,
            ["1.3.6.1.5.5.7.6.42"] = CertificateKeyAlgorithm.MlDsa65Rsa3072Pkcs15Sha512,
            ["1.3.6.1.5.5.7.6.43"] = CertificateKeyAlgorithm.MlDsa65Rsa4096PssSha512,
            ["1.3.6.1.5.5.7.6.44"] = CertificateKeyAlgorithm.MlDsa65Rsa4096Pkcs15Sha512,
            ["1.3.6.1.5.5.7.6.45"] = CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512,
            ["1.3.6.1.5.5.7.6.46"] = CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512,
            ["1.3.6.1.5.5.7.6.47"] = CertificateKeyAlgorithm.MlDsa65EcdsaBrainpoolP256r1Sha512,
            ["1.3.6.1.5.5.7.6.48"] = CertificateKeyAlgorithm.MlDsa65Ed25519Sha512,
            ["1.3.6.1.5.5.7.6.49"] = CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512,
            ["1.3.6.1.5.5.7.6.50"] = CertificateKeyAlgorithm.MlDsa87EcdsaBrainpoolP384r1Sha512,
            ["1.3.6.1.5.5.7.6.51"] = CertificateKeyAlgorithm.MlDsa87Ed448Shake256,
            ["1.3.6.1.5.5.7.6.52"] = CertificateKeyAlgorithm.MlDsa87Rsa3072PssSha512,
            ["1.3.6.1.5.5.7.6.53"] = CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512,
            ["1.3.6.1.5.5.7.6.54"] = CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512,
        };

    /// <summary>Returns the canonical wire-format string for the algorithm (e.g. <c>"ECDSA-P256"</c>).</summary>
    public static string ToCanonicalString(this CertificateKeyAlgorithm algorithm) => algorithm switch
    {
        CertificateKeyAlgorithm.Rsa => "RSA",
        CertificateKeyAlgorithm.EcdsaP256 => "ECDSA-P256",
        CertificateKeyAlgorithm.EcdsaP384 => "ECDSA-P384",
        CertificateKeyAlgorithm.MlDsa44 => "ML-DSA-44",
        CertificateKeyAlgorithm.SlhDsaSha2128s => "SLH-DSA-SHA2-128S",
        CertificateKeyAlgorithm.SlhDsaSha2128f => "SLH-DSA-SHA2-128F",
        CertificateKeyAlgorithm.MlDsa65 => "ML-DSA-65",
        CertificateKeyAlgorithm.MlDsa87 => "ML-DSA-87",
        CertificateKeyAlgorithm.HybridEcdsaP256 => "HYBRID-ECDSA-P256",
        CertificateKeyAlgorithm.HybridEcdsaP384 => "HYBRID-ECDSA-P384",
        CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256 => "MLDSA44-RSA2048-PSS-SHA256",
        CertificateKeyAlgorithm.MlDsa44Rsa2048Pkcs15Sha256 => "MLDSA44-RSA2048-PKCS15-SHA256",
        CertificateKeyAlgorithm.MlDsa44Ed25519Sha512 => "MLDSA44-Ed25519-SHA512",
        CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256 => "MLDSA44-ECDSA-P256-SHA256",
        CertificateKeyAlgorithm.MlDsa65Rsa3072PssSha512 => "MLDSA65-RSA3072-PSS-SHA512",
        CertificateKeyAlgorithm.MlDsa65Rsa3072Pkcs15Sha512 => "MLDSA65-RSA3072-PKCS15-SHA512",
        CertificateKeyAlgorithm.MlDsa65Rsa4096PssSha512 => "MLDSA65-RSA4096-PSS-SHA512",
        CertificateKeyAlgorithm.MlDsa65Rsa4096Pkcs15Sha512 => "MLDSA65-RSA4096-PKCS15-SHA512",
        CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512 => "MLDSA65-ECDSA-P256-SHA512",
        CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512 => "MLDSA65-ECDSA-P384-SHA512",
        CertificateKeyAlgorithm.MlDsa65EcdsaBrainpoolP256r1Sha512 => "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        CertificateKeyAlgorithm.MlDsa65Ed25519Sha512 => "MLDSA65-Ed25519-SHA512",
        CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512 => "MLDSA87-ECDSA-P384-SHA512",
        CertificateKeyAlgorithm.MlDsa87EcdsaBrainpoolP384r1Sha512 => "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        CertificateKeyAlgorithm.MlDsa87Ed448Shake256 => "MLDSA87-Ed448-SHAKE256",
        CertificateKeyAlgorithm.MlDsa87Rsa3072PssSha512 => "MLDSA87-RSA3072-PSS-SHA512",
        CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512 => "MLDSA87-RSA4096-PSS-SHA512",
        CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512 => "MLDSA87-ECDSA-P521-SHA512",
        CertificateKeyAlgorithm.MlKem512 => "ML-KEM-512",
        CertificateKeyAlgorithm.MlKem768 => "ML-KEM-768",
        CertificateKeyAlgorithm.MlKem1024 => "ML-KEM-1024",
        CertificateKeyAlgorithm.PairMlDsa44MlKem512 => "PAIR-ML-DSA-44-ML-KEM-512",
        CertificateKeyAlgorithm.PairMlDsa65MlKem768 => "PAIR-ML-DSA-65-ML-KEM-768",
        CertificateKeyAlgorithm.PairMlDsa87MlKem1024 => "PAIR-ML-DSA-87-ML-KEM-1024",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
    };

    /// <summary>
    /// Parses a canonical algorithm string (e.g. <c>"ECDSA-P256"</c>) to a <see cref="CertificateKeyAlgorithm"/>.
    /// Returns <see langword="null"/> for unknown or null inputs.
    /// </summary>
    public static CertificateKeyAlgorithm? Parse(string? value) => value?.ToUpperInvariant() switch
    {
        "RSA" => CertificateKeyAlgorithm.Rsa,
        "ECDSA-P256" => CertificateKeyAlgorithm.EcdsaP256,
        "ECDSA-P384" => CertificateKeyAlgorithm.EcdsaP384,
        "ML-DSA-44" => CertificateKeyAlgorithm.MlDsa44,
        "SLH-DSA-SHA2-128S" => CertificateKeyAlgorithm.SlhDsaSha2128s,
        "SLH-DSA-SHA2-128F" => CertificateKeyAlgorithm.SlhDsaSha2128f,
        "ML-DSA-65" => CertificateKeyAlgorithm.MlDsa65,
        "ML-DSA-87" => CertificateKeyAlgorithm.MlDsa87,
        "HYBRID-ECDSA-P256" => CertificateKeyAlgorithm.HybridEcdsaP256,
        "HYBRID-ECDSA-P384" => CertificateKeyAlgorithm.HybridEcdsaP384,
        "MLDSA44-RSA2048-PSS-SHA256" => CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256,
        "MLDSA44-RSA2048-PKCS15-SHA256" => CertificateKeyAlgorithm.MlDsa44Rsa2048Pkcs15Sha256,
        "MLDSA44-ED25519-SHA512" => CertificateKeyAlgorithm.MlDsa44Ed25519Sha512,
        "MLDSA44-ECDSA-P256-SHA256" => CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256,
        "MLDSA65-RSA3072-PSS-SHA512" => CertificateKeyAlgorithm.MlDsa65Rsa3072PssSha512,
        "MLDSA65-RSA3072-PKCS15-SHA512" => CertificateKeyAlgorithm.MlDsa65Rsa3072Pkcs15Sha512,
        "MLDSA65-RSA4096-PSS-SHA512" => CertificateKeyAlgorithm.MlDsa65Rsa4096PssSha512,
        "MLDSA65-RSA4096-PKCS15-SHA512" => CertificateKeyAlgorithm.MlDsa65Rsa4096Pkcs15Sha512,
        "MLDSA65-ECDSA-P256-SHA512" => CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512,
        "MLDSA65-ECDSA-P384-SHA512" => CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512,
        "MLDSA65-ECDSA-BRAINPOOLP256R1-SHA512" => CertificateKeyAlgorithm.MlDsa65EcdsaBrainpoolP256r1Sha512,
        "MLDSA65-ED25519-SHA512" => CertificateKeyAlgorithm.MlDsa65Ed25519Sha512,
        "MLDSA87-ECDSA-P384-SHA512" => CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512,
        "MLDSA87-ECDSA-BRAINPOOLP384R1-SHA512" => CertificateKeyAlgorithm.MlDsa87EcdsaBrainpoolP384r1Sha512,
        "MLDSA87-ED448-SHAKE256" => CertificateKeyAlgorithm.MlDsa87Ed448Shake256,
        "MLDSA87-RSA3072-PSS-SHA512" => CertificateKeyAlgorithm.MlDsa87Rsa3072PssSha512,
        "MLDSA87-RSA4096-PSS-SHA512" => CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512,
        "MLDSA87-ECDSA-P521-SHA512" => CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512,
        "ML-KEM-512" => CertificateKeyAlgorithm.MlKem512,
        "ML-KEM-768" => CertificateKeyAlgorithm.MlKem768,
        "ML-KEM-1024" => CertificateKeyAlgorithm.MlKem1024,
        "PAIR-ML-DSA-44-ML-KEM-512" => CertificateKeyAlgorithm.PairMlDsa44MlKem512,
        "PAIR-ML-DSA-65-ML-KEM-768" => CertificateKeyAlgorithm.PairMlDsa65MlKem768,
        "PAIR-ML-DSA-87-ML-KEM-1024" => CertificateKeyAlgorithm.PairMlDsa87MlKem1024,
        _ => null
    };

    /// <summary>Returns the <see cref="AlgorithmFamily"/> that this algorithm belongs to.</summary>
    public static AlgorithmFamily GetFamily(this CertificateKeyAlgorithm algorithm) => algorithm switch
    {
        CertificateKeyAlgorithm.Rsa => AlgorithmFamily.Rsa,
        CertificateKeyAlgorithm.EcdsaP256 or CertificateKeyAlgorithm.EcdsaP384 => AlgorithmFamily.Ecdsa,
        CertificateKeyAlgorithm.MlDsa44 or CertificateKeyAlgorithm.MlDsa65 or CertificateKeyAlgorithm.MlDsa87
            or CertificateKeyAlgorithm.SlhDsaSha2128s or CertificateKeyAlgorithm.SlhDsaSha2128f => AlgorithmFamily.Pqc,
        CertificateKeyAlgorithm.HybridEcdsaP256 or CertificateKeyAlgorithm.HybridEcdsaP384 => AlgorithmFamily.Hybrid,
        CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256 or CertificateKeyAlgorithm.MlDsa44Rsa2048Pkcs15Sha256
            or CertificateKeyAlgorithm.MlDsa44Ed25519Sha512 or CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256
            or CertificateKeyAlgorithm.MlDsa65Rsa3072PssSha512 or CertificateKeyAlgorithm.MlDsa65Rsa3072Pkcs15Sha512
            or CertificateKeyAlgorithm.MlDsa65Rsa4096PssSha512 or CertificateKeyAlgorithm.MlDsa65Rsa4096Pkcs15Sha512
            or CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512 or CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512
            or CertificateKeyAlgorithm.MlDsa65EcdsaBrainpoolP256r1Sha512 or CertificateKeyAlgorithm.MlDsa65Ed25519Sha512
            or CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512 or CertificateKeyAlgorithm.MlDsa87EcdsaBrainpoolP384r1Sha512
            or CertificateKeyAlgorithm.MlDsa87Ed448Shake256 or CertificateKeyAlgorithm.MlDsa87Rsa3072PssSha512
            or CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512 or CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512 => AlgorithmFamily.Composite,
        CertificateKeyAlgorithm.MlKem512 or CertificateKeyAlgorithm.MlKem768 or CertificateKeyAlgorithm.MlKem1024 => AlgorithmFamily.Kem,
        CertificateKeyAlgorithm.PairMlDsa44MlKem512 or CertificateKeyAlgorithm.PairMlDsa65MlKem768
            or CertificateKeyAlgorithm.PairMlDsa87MlKem1024 => AlgorithmFamily.Pair,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null)
    };

    /// <summary>
    /// Whether a key of this algorithm can produce a signature, and so can be a CA key: false for
    /// <see cref="AlgorithmFamily.Kem"/> and for <see cref="AlgorithmFamily.Pair"/>, which holds an
    /// encryption-only key. A key that cannot sign cannot be a CA, and a CSR carrying one cannot prove
    /// possession, so display and validation code outside <c>Qertum.Services</c> asks this rather than
    /// listing families.
    /// </summary>
    public static bool CanSign(this CertificateKeyAlgorithm algorithm) =>
        algorithm.GetFamily() is not (AlgorithmFamily.Kem or AlgorithmFamily.Pair);

    /// <summary>
    /// Whether the algorithm issues two certificates from one request: a classical + PQC
    /// <see cref="AlgorithmFamily.Hybrid"/> pair or a post-quantum signing + encryption
    /// <see cref="AlgorithmFamily.Pair"/>. The first certificate is stored in the certificate and private-key
    /// fields, the second in the <c>Pqc*</c> fields.
    /// </summary>
    public static bool IsPaired(this CertificateKeyAlgorithm algorithm) =>
        algorithm.GetFamily() is AlgorithmFamily.Hybrid or AlgorithmFamily.Pair;
}

/// <summary>
/// Serializes <see cref="CertificateKeyAlgorithm"/> as its canonical string (e.g. <c>"ECDSA-P256"</c>)
/// rather than as an integer, matching the wire format used in the database and API.
/// </summary>
public sealed class CertificateKeyAlgorithmJsonConverter : JsonConverter<CertificateKeyAlgorithm>
{
    /// <inheritdoc/>
    public override CertificateKeyAlgorithm Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var str = reader.GetString();
        return CertificateKeyAlgorithmExtensions.Parse(str)
            ?? throw new JsonException($"Unknown key algorithm: '{str}'.");
    }

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, CertificateKeyAlgorithm value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToCanonicalString());
}
