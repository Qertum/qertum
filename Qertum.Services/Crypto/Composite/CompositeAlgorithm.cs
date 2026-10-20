using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;

namespace Qertum.Services.Crypto.Composite;

/// <summary>The traditional half of a composite ML-DSA algorithm (draft-ietf-lamps-pq-composite-sigs-19 §6).</summary>
public enum CompositeTraditional
{
    RsaPss,
    RsaPkcs15,
    Ecdsa,
    Ed25519,
    Ed448
}

/// <summary>The pre-hash PH applied to the message before the message representative M' is built (§2.1).</summary>
public enum CompositePreHash
{
    Sha256,
    Sha512,
    Shake256With64ByteOutput
}

/// <summary>
/// One composite ML-DSA algorithm, exactly as draft -19 §6 defines it. Every fact about a combination —
/// OID, label, ML-DSA parameter set, traditional component, digests — lives here and nowhere else.
/// </summary>
/// <param name="Name">The draft's identifier without the <c>id-</c> prefix, e.g. <c>MLDSA65-ECDSA-P256-SHA512</c>.</param>
/// <param name="Oid">The IANA-allocated OID under <c>1.3.6.1.5.5.7.6</c>.</param>
/// <param name="Label">The signature label bound into M' and passed to ML-DSA as its context.</param>
/// <param name="MlDsa">The ML-DSA parameter set.</param>
/// <param name="Traditional">The traditional signature scheme.</param>
/// <param name="RsaKeyBits">RSA modulus size; 0 for non-RSA combinations.</param>
/// <param name="CurveName">The ECDSA curve name BouncyCastle knows it by; null for non-ECDSA combinations.</param>
/// <param name="TraditionalDigest">The digest the RSA or ECDSA component signs M' with (BouncyCastle name); null for EdDSA.</param>
/// <param name="PreHash">The pre-hash PH.</param>
public sealed record CompositeAlgorithm(
    string Name,
    DerObjectIdentifier Oid,
    string Label,
    MLDsaParameters MlDsa,
    CompositeTraditional Traditional,
    int RsaKeyBits,
    string? CurveName,
    string? TraditionalDigest,
    CompositePreHash PreHash)
{
    /// <summary>Encoded ML-DSA public-key length; the composite public key splits here (§4.1).</summary>
    public int MlDsaPublicKeyLength => MlDsaSizes.PublicKey;

    /// <summary>Encoded ML-DSA signature length; the composite signature splits here (§4.3).</summary>
    public int MlDsaSignatureLength => MlDsaSizes.Signature;

    /// <summary>RSASSA-PSS salt length: 32 bytes with SHA-256 (2048/3072), 48 with SHA-384 (4096), per §6.1.</summary>
    public int PssSaltLength => RsaKeyBits == 4096 ? 48 : 32;

    private (int PublicKey, int Signature) MlDsaSizes =>
        MlDsa == MLDsaParameters.ml_dsa_44 ? (1312, 2420)
        : MlDsa == MLDsaParameters.ml_dsa_65 ? (1952, 3309)
        : MlDsa == MLDsaParameters.ml_dsa_87 ? (2592, 4627)
        : throw new InvalidOperationException($"No ML-DSA sizes are known for '{MlDsa.Name}'.");
}
