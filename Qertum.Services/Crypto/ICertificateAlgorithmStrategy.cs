using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

/// <summary>
/// Encapsulates the algorithm-specific rules for a subject key: key pair generation and key usage
/// bit mapping. Every algorithm Qertum can issue a certificate for has one. Implement this
/// interface to add support for a new key algorithm without modifying
/// <see cref="CertificateGenerator"/>; implement <see cref="IIssuerAlgorithmStrategy"/> as well only
/// if a key of that algorithm can sign certificates.
/// </summary>
public interface ICertificateAlgorithmStrategy
{
    /// <summary>Generates a key pair for a leaf certificate.</summary>
    AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random);

    /// <summary>
    /// Maps a set of requested key usage names (e.g., "DigitalSignature", "KeyEncipherment")
    /// to the BouncyCastle <see cref="Org.BouncyCastle.Asn1.X509.KeyUsage"/> bit mask.
    /// Returns the algorithm's default bits when <paramref name="requestedUsages"/> is empty.
    /// </summary>
    int BuildKeyUsageBits(IEnumerable<string> requestedUsages);
}

/// <summary>
/// A strategy whose keys can sign, and so can hold a CA key. Only
/// <see cref="AlgorithmStrategyFactory.CreateIssuer"/> and
/// <see cref="AlgorithmStrategyFactory.CreateFromPrivateKey"/> hand these out, which makes root
/// eligibility a property of the type rather than of which factory call happens to throw.
/// </summary>
public interface IIssuerAlgorithmStrategy : ICertificateAlgorithmStrategy
{
    /// <summary>Generates a key pair for a root CA certificate (may use larger keys than leaf).</summary>
    AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random);

    /// <summary>The OID / algorithm name used by a CA of this key type to sign certificates.</summary>
    string CaSignatureAlgorithm { get; }
}
