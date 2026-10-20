using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

/// <summary>
/// ML-KEM (FIPS 203) subject keys. A subject-key strategy only: a KEM key cannot sign, so this
/// deliberately does not implement <see cref="IIssuerAlgorithmStrategy"/> and can never be a CA.
/// </summary>
internal sealed class MlKemAlgorithmStrategy : ICertificateAlgorithmStrategy
{
    private readonly MLKemParameters _parameters;

    internal MlKemAlgorithmStrategy(CertificateKeyAlgorithm algorithm)
    {
        // Exhaustive for the same reason as MlDsaAlgorithmStrategy: a default arm would issue a
        // key of one parameter set under the name of another.
        _parameters = algorithm switch
        {
            CertificateKeyAlgorithm.MlKem512 => MLKemParameters.ml_kem_512,
            CertificateKeyAlgorithm.MlKem768 => MLKemParameters.ml_kem_768,
            CertificateKeyAlgorithm.MlKem1024 => MLKemParameters.ml_kem_1024,
            _ => throw new NotSupportedException($"{algorithm} is not an ML-KEM parameter set.")
        };
    }

    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random)
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(random, _parameters));
        return generator.GenerateKeyPair();
    }

    /// <summary>
    /// Always <c>keyEncipherment</c>, the only usage the IETF ML-KEM certificate profile permits.
    /// Whatever else a template asks for — signature bits a KEM key cannot honour, or
    /// <c>keyAgreement</c>, which describes Diffie-Hellman rather than encapsulation — is dropped.
    /// </summary>
    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages) => KeyUsage.KeyEncipherment;
}
