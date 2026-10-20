using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// §3.1 KeyGen: both component keys are generated fresh, together, every time. There is
/// deliberately no way to build a composite key from existing component keys — the draft forbids
/// reusing a component key on its own or in another combination.
/// </summary>
public static class CompositeKeyPairGenerator
{
    public static AsymmetricCipherKeyPair Generate(CompositeAlgorithm algorithm, SecureRandom random)
    {
        var seed = new byte[32];
        random.NextBytes(seed);
        var privateKey = new CompositePrivateKey(
            algorithm,
            MLDsaPrivateKeyParameters.FromSeed(algorithm.MlDsa, seed),
            CompositeTraditionalKeys.Generate(algorithm, random).Private);
        return new AsymmetricCipherKeyPair(privateKey.PublicKey, privateKey);
    }
}
