using System.Linq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto;

internal sealed class RsaAlgorithmStrategy : IIssuerAlgorithmStrategy
{
    public AsymmetricCipherKeyPair GenerateLeafKeyPair(SecureRandom random) => Generate(2048, random);
    public AsymmetricCipherKeyPair GenerateCaKeyPair(SecureRandom random) => Generate(4096, random);
    public string CaSignatureAlgorithm => "SHA256WITHRSA";

    public int BuildKeyUsageBits(IEnumerable<string> requestedUsages)
    {
        var bits = requestedUsages.Aggregate(0, (acc, usage) => acc | (usage switch
        {
            "DigitalSignature"              => KeyUsage.DigitalSignature,
            "NonRepudiation"                => KeyUsage.NonRepudiation,
            "KeyEncipherment" or "KeyAgreement" => KeyUsage.KeyEncipherment,
            "DataEncipherment"              => KeyUsage.DataEncipherment,
            "KeyCertSign"                   => KeyUsage.KeyCertSign,
            "CrlSign"                       => KeyUsage.CrlSign,
            "EncipherOnly"                  => KeyUsage.EncipherOnly,
            "DecipherOnly"                  => KeyUsage.DecipherOnly,
            _                               => 0
        }));
        return bits == 0 ? KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment : bits;
    }

    private static AsymmetricCipherKeyPair Generate(int keySize, SecureRandom random)
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(random, keySize));
        return gen.GenerateKeyPair();
    }
}
