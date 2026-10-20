using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Services.Crypto;

/// <summary>
/// Creates the appropriate <see cref="ICertificateAlgorithmStrategy"/> from a
/// <see cref="CertificateKeyAlgorithm"/> or an existing <see cref="AsymmetricKeyParameter"/>.
/// Add a new case here when introducing a new key algorithm: in <see cref="CreateIssuer"/> if its
/// keys can sign (which makes it root-eligible), in <see cref="Create"/> alone if they cannot.
/// </summary>
public static class AlgorithmStrategyFactory
{
    /// <summary>
    /// Returns the subject-key strategy for the given algorithm: what issuing a certificate
    /// <em>for</em> a key of this algorithm needs. Says nothing about whether it may be a CA —
    /// that is <see cref="CreateIssuer"/>.
    /// </summary>
    /// <exception cref="NotSupportedException">Thrown for Hybrid values; those are orchestrated at a higher level.</exception>
    public static ICertificateAlgorithmStrategy Create(CertificateKeyAlgorithm algorithm) =>
        algorithm.GetFamily() == AlgorithmFamily.Kem
            ? new MlKemAlgorithmStrategy(algorithm)
            : CreateIssuer(algorithm);

    /// <summary>
    /// Returns the strategy for a CA key of the given algorithm. This is the one decision on which
    /// algorithms may be a root: onboarding and <see cref="CertificateGenerator.GenerateCa"/> go
    /// through it, so an algorithm is root-eligible exactly when it has an arm here.
    /// </summary>
    /// <exception cref="NotSupportedException">
    /// Thrown for Hybrid values (a pair is two certificates, not one CA key) and for KEM values (a
    /// KEM key cannot sign).
    /// </exception>
    public static IIssuerAlgorithmStrategy CreateIssuer(CertificateKeyAlgorithm algorithm) =>
        algorithm switch
        {
            CertificateKeyAlgorithm.Rsa                                       => new RsaAlgorithmStrategy(),
            CertificateKeyAlgorithm.EcdsaP256 or CertificateKeyAlgorithm.EcdsaP384 => new EcAlgorithmStrategy(algorithm),
            CertificateKeyAlgorithm.MlDsa44   or CertificateKeyAlgorithm.MlDsa65
                                              or CertificateKeyAlgorithm.MlDsa87   => new MlDsaAlgorithmStrategy(algorithm),
            CertificateKeyAlgorithm.SlhDsaSha2128s
                or CertificateKeyAlgorithm.SlhDsaSha2128f                          => new SlhDsaAlgorithmStrategy(algorithm),
            // Makes all 18 composite algorithms root-eligible, deliberately.
            _ when algorithm.GetFamily() == AlgorithmFamily.Composite            => new CompositeAlgorithmStrategy(CompositeAlgorithms.For(algorithm)),
            _ when algorithm.GetFamily() == AlgorithmFamily.Kem => throw new NotSupportedException(
                $"'{algorithm.ToCanonicalString()}' is a key encapsulation algorithm; it cannot sign, so it cannot be a CA key."),
            _ => throw new NotSupportedException(
                $"Algorithm '{algorithm}' has no dedicated strategy. Paired algorithms (hybrid and signing + encryption) are orchestrated by {nameof(CertificateGenerator)} directly.")
        };

    /// <summary>Infers the strategy from an existing private key (e.g., to determine the CA signing algorithm).</summary>
    /// <exception cref="NotSupportedException">Thrown for an ML-KEM key, which cannot sign.</exception>
    public static IIssuerAlgorithmStrategy CreateFromPrivateKey(AsymmetricKeyParameter privateKey) =>
        privateKey switch
        {
            // Before the RSA default arm below, which would otherwise call a KEM key an RSA signer.
            MLKemPrivateKeyParameters => throw new NotSupportedException(
                "An ML-KEM key cannot sign, so it cannot be a CA key."),
            // First: the RSA default arm below would otherwise claim a composite key.
            CompositePrivateKey composite => new CompositeAlgorithmStrategy(composite.Algorithm),
            // Same reason as the parameter-set switch in MlDsaAlgorithmStrategy: a ternary here
            // relabelled every non-87 ML-DSA key as ML-DSA-65.
            SlhDsaPrivateKeyParameters slhDsa => new SlhDsaAlgorithmStrategy(slhDsa.Parameters),
            MLDsaPrivateKeyParameters mlDsa =>
                new MlDsaAlgorithmStrategy(
                    mlDsa.Parameters == MLDsaParameters.ml_dsa_44 ? CertificateKeyAlgorithm.MlDsa44
                    : mlDsa.Parameters == MLDsaParameters.ml_dsa_87 ? CertificateKeyAlgorithm.MlDsa87
                    : CertificateKeyAlgorithm.MlDsa65),
            ECPrivateKeyParameters ec =>
                new EcAlgorithmStrategy(ec.Parameters.N.BitLength >= 384
                    ? CertificateKeyAlgorithm.EcdsaP384 : CertificateKeyAlgorithm.EcdsaP256),
            _ => new RsaAlgorithmStrategy()
        };
}
