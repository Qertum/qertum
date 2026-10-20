using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

internal sealed class MlDsaAlgorithmStrategy : IIssuerAlgorithmStrategy
{
    private readonly MLDsaParameters _parameters;

    internal MlDsaAlgorithmStrategy(CertificateKeyAlgorithm algorithm)
    {
        // Exhaustive on purpose. This was a ternary defaulting to ml_dsa_65, which silently
        // produced an ML-DSA-65 key for any ML-DSA value that was not 87 — a certificate on
        // record under an algorithm it does not have. A new parameter set must fail loudly here.
        _parameters = algorithm switch
        {
            CertificateKeyAlgorithm.MlDsa44 => MLDsaParameters.ml_dsa_44,
            CertificateKeyAlgorithm.MlDsa65 => MLDsaParameters.ml_dsa_65,
            CertificateKeyAlgorithm.MlDsa87 => MLDsaParameters.ml_dsa_87,
            _ => throw new NotSupportedException($"{algorithm} is not an ML-DSA parameter set.")
        };
    }

    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random) => Generate(random);
    public AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random) => Generate(random);
    public string CaSignatureAlgorithm =>
        _parameters == MLDsaParameters.ml_dsa_44 ? "ML-DSA-44"
        : _parameters == MLDsaParameters.ml_dsa_87 ? "ML-DSA-87"
        : "ML-DSA-65";

    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages)
    {
        // ML-DSA is signature-only; key-exchange bits (KeyEncipherment, DataEncipherment,
        // KeyAgreement, EncipherOnly, DecipherOnly) are silently dropped.
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
        var gen = new MLDsaKeyPairGenerator();
        gen.Init(new MLDsaKeyGenerationParameters(random, _parameters));
        return gen.GenerateKeyPair();
    }
}
