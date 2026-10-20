using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using static Org.BouncyCastle.Asn1.Iana.IanaObjectIdentifiers;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// The 18 composite ML-DSA algorithms of draft-ietf-lamps-pq-composite-sigs-19 §6. The OIDs are
/// BouncyCastle's <c>IanaObjectIdentifiers</c> (the IANA early allocation of 2025-10-20), never the
/// older Entrust-arc <c>BCObjectIdentifiers</c> set. <c>CompositeAlgorithmsTests</c> pins every row
/// against the draft.
/// </summary>
public static class CompositeAlgorithms
{
    private static readonly MLDsaParameters L44 = MLDsaParameters.ml_dsa_44;
    private static readonly MLDsaParameters L65 = MLDsaParameters.ml_dsa_65;
    private static readonly MLDsaParameters L87 = MLDsaParameters.ml_dsa_87;

    /// <summary>All 18 algorithms, in OID order.</summary>
    public static IReadOnlyList<CompositeAlgorithm> All { get; } =
    [
        new("MLDSA44-RSA2048-PSS-SHA256", id_MLDSA44_RSA2048_PSS_SHA256, "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", L44, CompositeTraditional.RsaPss, 2048, null, "SHA-256", CompositePreHash.Sha256),
        new("MLDSA44-RSA2048-PKCS15-SHA256", id_MLDSA44_RSA2048_PKCS15_SHA256, "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", L44, CompositeTraditional.RsaPkcs15, 2048, null, "SHA-256", CompositePreHash.Sha256),
        new("MLDSA44-Ed25519-SHA512", id_MLDSA44_Ed25519_SHA512, "COMPSIG-MLDSA44-Ed25519-SHA512", L44, CompositeTraditional.Ed25519, 0, null, null, CompositePreHash.Sha512),
        new("MLDSA44-ECDSA-P256-SHA256", id_MLDSA44_ECDSA_P256_SHA256, "COMPSIG-MLDSA44-ECDSA-P256-SHA256", L44, CompositeTraditional.Ecdsa, 0, "secp256r1", "SHA-256", CompositePreHash.Sha256),
        new("MLDSA65-RSA3072-PSS-SHA512", id_MLDSA65_RSA3072_PSS_SHA512, "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", L65, CompositeTraditional.RsaPss, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-RSA3072-PKCS15-SHA512", id_MLDSA65_RSA3072_PKCS15_SHA512, "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", L65, CompositeTraditional.RsaPkcs15, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-RSA4096-PSS-SHA512", id_MLDSA65_RSA4096_PSS_SHA512, "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", L65, CompositeTraditional.RsaPss, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-RSA4096-PKCS15-SHA512", id_MLDSA65_RSA4096_PKCS15_SHA512, "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", L65, CompositeTraditional.RsaPkcs15, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-P256-SHA512", id_MLDSA65_ECDSA_P256_SHA512, "COMPSIG-MLDSA65-ECDSA-P256-SHA512", L65, CompositeTraditional.Ecdsa, 0, "secp256r1", "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-P384-SHA512", id_MLDSA65_ECDSA_P384_SHA512, "COMPSIG-MLDSA65-ECDSA-P384-SHA512", L65, CompositeTraditional.Ecdsa, 0, "secp384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-brainpoolP256r1-SHA512", id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", L65, CompositeTraditional.Ecdsa, 0, "brainpoolP256r1", "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-Ed25519-SHA512", id_MLDSA65_Ed25519_SHA512, "COMPSIG-MLDSA65-Ed25519-SHA512", L65, CompositeTraditional.Ed25519, 0, null, null, CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-P384-SHA512", id_MLDSA87_ECDSA_P384_SHA512, "COMPSIG-MLDSA87-ECDSA-P384-SHA512", L87, CompositeTraditional.Ecdsa, 0, "secp384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-brainpoolP384r1-SHA512", id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", L87, CompositeTraditional.Ecdsa, 0, "brainpoolP384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-Ed448-SHAKE256", id_MLDSA87_Ed448_SHAKE256, "COMPSIG-MLDSA87-Ed448-SHAKE256", L87, CompositeTraditional.Ed448, 0, null, null, CompositePreHash.Shake256With64ByteOutput),
        new("MLDSA87-RSA3072-PSS-SHA512", id_MLDSA87_RSA3072_PSS_SHA512, "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", L87, CompositeTraditional.RsaPss, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA87-RSA4096-PSS-SHA512", id_MLDSA87_RSA4096_PSS_SHA512, "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", L87, CompositeTraditional.RsaPss, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-P521-SHA512", id_MLDSA87_ECDSA_P521_SHA512, "COMPSIG-MLDSA87-ECDSA-P521-SHA512", L87, CompositeTraditional.Ecdsa, 0, "secp521r1", "SHA-512", CompositePreHash.Sha512),
    ];

    private static readonly Dictionary<string, CompositeAlgorithm> ByOid = All.ToDictionary(a => a.Oid.Id, StringComparer.Ordinal);

    /// <summary>The composite algorithm with this OID, or null when the OID is not a composite one.</summary>
    public static CompositeAlgorithm? FindByOid(DerObjectIdentifier oid) => ByOid.GetValueOrDefault(oid.Id);

    /// <summary>The composite algorithm with this name (case-insensitive), or null.</summary>
    public static CompositeAlgorithm? FindByName(string name) =>
        All.FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// The registry row for a <see cref="AlgorithmFamily.Composite"/> value. Joined on the canonical
    /// string, which is the draft name in both places; <c>CompositeAlgorithmsTests</c> pins that every
    /// composite enum value has a row and every row has a value.
    /// </summary>
    public static CompositeAlgorithm For(CertificateKeyAlgorithm algorithm) =>
        algorithm.GetFamily() == AlgorithmFamily.Composite
            ? FindByName(algorithm.ToCanonicalString())
              ?? throw new InvalidOperationException($"{algorithm} has no composite registry row.")
            : throw new ArgumentException($"{algorithm} is not a composite algorithm.", nameof(algorithm));

    /// <summary>The <see cref="CertificateKeyAlgorithm"/> value this row is stored and sent as.</summary>
    public static CertificateKeyAlgorithm ToKeyAlgorithm(this CompositeAlgorithm algorithm) =>
        CertificateKeyAlgorithmExtensions.Parse(algorithm.Name)
        ?? throw new InvalidOperationException($"{algorithm.Name} has no CertificateKeyAlgorithm value.");
}
