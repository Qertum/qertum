using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

internal sealed class EcAlgorithmStrategy : IIssuerAlgorithmStrategy
{
    private readonly string _curveName;

    internal EcAlgorithmStrategy(CertificateKeyAlgorithm algorithm)
    {
        _curveName = algorithm == CertificateKeyAlgorithm.EcdsaP384 ? "P-384" : "P-256";
    }

    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random) => Generate(random);
    public AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random) => Generate(random);
    public string CaSignatureAlgorithm => _curveName == "P-384" ? "SHA384WITHECDSA" : "SHA256WITHECDSA";

    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages)
    {
        var bits = requestedUsages.Aggregate(0, (acc, usage) => acc | (usage switch
        {
            "DigitalSignature"              => KeyUsage.DigitalSignature,
            "NonRepudiation"                => KeyUsage.NonRepudiation,
            "KeyEncipherment" or "KeyAgreement" => KeyUsage.KeyAgreement,
            "DataEncipherment"              => KeyUsage.DataEncipherment,
            "KeyCertSign"                   => KeyUsage.KeyCertSign,
            "CrlSign"                       => KeyUsage.CrlSign,
            "EncipherOnly"                  => KeyUsage.EncipherOnly,
            "DecipherOnly"                  => KeyUsage.DecipherOnly,
            _                               => 0
        }));
        return bits == 0 ? KeyUsage.DigitalSignature | KeyUsage.KeyAgreement : bits;
    }

    private AsymmetricCipherKeyPair Generate(SecureRandom random)
    {
        // The OID constructor yields ECNamedDomainParameters, so the key is encoded with its curve's
        // name (RFC 5480 §2.1.1). Bare ECDomainParameters would spell the curve out, which OpenSSL 3
        // refuses for a CA key in a chain.
        var curveOid = ECNamedCurveTable.GetOid(_curveName)
            ?? throw new ArgumentException($"Unknown EC curve: {_curveName}");
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(curveOid, random));
        return gen.GenerateKeyPair();
    }
}
