using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// The one strategy for all 18 composite algorithms. The draft fixes both component key sizes per
/// combination, so leaf and CA keys are generated the same way.
/// </summary>
internal sealed class CompositeAlgorithmStrategy(CompositeAlgorithm algorithm) : IIssuerAlgorithmStrategy
{
    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random) => CompositeKeyPairGenerator.Generate(algorithm, random);

    public AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random) => CompositeKeyPairGenerator.Generate(algorithm, random);

    public string CaSignatureAlgorithm => algorithm.Name;

    /// <summary>
    /// Signature bits only (draft -19 §5.2): digitalSignature, nonRepudiation, keyCertSign, cRLSign.
    /// Key-exchange bits are dropped, as for ML-DSA.
    /// </summary>
    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages)
    {
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
}
