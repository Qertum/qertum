using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

/// <summary>
/// SLH-DSA (FIPS 205), the stateless hash-based signature scheme. The SHA2 sets at security
/// levels 1, 3 and 5 (128, 192, 256) are offered: "s" for the smaller signature and "f" for the
/// faster one. The SHAKE sets are not.
/// </summary>
/// <remarks>
/// The canonical algorithm strings are also BouncyCastle's own signer names, so they go straight
/// to <c>Asn1SignatureFactory</c> with no mapping table.
/// Two operational notes for anyone widening this: the signature lives in the certificate, so an
/// SLH-DSA issuer adds roughly 8 KB (128s) to 50 KB (256f) to every certificate it signs and to
/// every chain those certificates are sent in; and signing costs hundreds of milliseconds for the
/// "s" sets, which is paid per issuance, not once.
/// </remarks>
internal sealed class SlhDsaAlgorithmStrategy : IIssuerAlgorithmStrategy
{
    private readonly SlhDsaParameters _parameters;
    private readonly string _name;

    internal SlhDsaAlgorithmStrategy(CertificateKeyAlgorithm algorithm)
    {
        // Exhaustive rather than a ternary: MlDsaAlgorithmStrategy once generated the wrong
        // parameter set for a third value; a new set must fail here instead of silently becoming
        // one of these.
        (_parameters, _name) = algorithm switch
        {
            CertificateKeyAlgorithm.SlhDsaSha2128s => (SlhDsaParameters.slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S"),
            CertificateKeyAlgorithm.SlhDsaSha2128f => (SlhDsaParameters.slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F"),
            CertificateKeyAlgorithm.SlhDsaSha2192s => (SlhDsaParameters.slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S"),
            CertificateKeyAlgorithm.SlhDsaSha2192f => (SlhDsaParameters.slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F"),
            CertificateKeyAlgorithm.SlhDsaSha2256s => (SlhDsaParameters.slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S"),
            CertificateKeyAlgorithm.SlhDsaSha2256f => (SlhDsaParameters.slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F"),
            _ => throw new NotSupportedException($"{algorithm} is not an SLH-DSA parameter set.")
        };
    }

    internal SlhDsaAlgorithmStrategy(SlhDsaParameters parameters)
        : this(FromParameters(parameters))
    {
    }

    /// <summary>Maps a BouncyCastle parameter set back to its enum value, exactly.</summary>
    internal static CertificateKeyAlgorithm FromParameters(SlhDsaParameters parameters) =>
        parameters == SlhDsaParameters.slh_dsa_sha2_128s ? CertificateKeyAlgorithm.SlhDsaSha2128s
        : parameters == SlhDsaParameters.slh_dsa_sha2_128f ? CertificateKeyAlgorithm.SlhDsaSha2128f
        : parameters == SlhDsaParameters.slh_dsa_sha2_192s ? CertificateKeyAlgorithm.SlhDsaSha2192s
        : parameters == SlhDsaParameters.slh_dsa_sha2_192f ? CertificateKeyAlgorithm.SlhDsaSha2192f
        : parameters == SlhDsaParameters.slh_dsa_sha2_256s ? CertificateKeyAlgorithm.SlhDsaSha2256s
        : parameters == SlhDsaParameters.slh_dsa_sha2_256f ? CertificateKeyAlgorithm.SlhDsaSha2256f
        : throw new NotSupportedException($"Unsupported SLH-DSA parameter set '{parameters}'.");

    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random) => Generate(random);
    public AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random) => Generate(random);
    public string CaSignatureAlgorithm => _name;

    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages)
    {
        // SLH-DSA is signature-only, same as ML-DSA: key-exchange bits (KeyEncipherment,
        // DataEncipherment, KeyAgreement, EncipherOnly, DecipherOnly) are silently dropped.
        var bits = requestedUsages.Aggregate(0, (acc, usage) => acc | (usage switch
        {
            "DigitalSignature" => KeyUsage.DigitalSignature,
            "NonRepudiation"   => KeyUsage.NonRepudiation,
            "KeyCertSign"      => KeyUsage.KeyCertSign,
            "CrlSign"          => KeyUsage.CrlSign,
            _                  => 0
        }));
        return bits == 0 ? KeyUsage.DigitalSignature : bits;
    }

    private AsymmetricCipherKeyPair Generate(SecureRandom random)
    {
        var gen = new SlhDsaKeyPairGenerator();
        gen.Init(new SlhDsaKeyGenerationParameters(random, _parameters));
        return gen.GenerateKeyPair();
    }
}
