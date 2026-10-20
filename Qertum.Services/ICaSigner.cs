using Qertum.Services.Crypto;
using Org.BouncyCastle.Crypto;

namespace Qertum.Services;

/// <summary>
/// Everything the CA needs from its private key, without handing the key over: a public key to name
/// itself with, the signature algorithm it signs under, and a factory that produces signatures.
/// </summary>
/// <remarks>
/// This is the seam a key that lives outside the process — Azure Key Vault, an HSM — plugs into.
/// A remote signer implements <see cref="CreateSignatureFactory"/> by sending a digest away and
/// receiving a signature, so the private key never has to exist in memory here. Keep every CA
/// signing path going through this interface: a call site that reaches for key material directly is
/// one that cannot be backed by a vault later.
/// </remarks>
public interface ICaSigner
{
    /// <summary>The CA's public key. Used where a structure must carry the CA's identity rather than sign.</summary>
    AsymmetricKeyParameter PublicKey { get; }

    /// <summary>Name of the signature algorithm this signer produces, e.g. <c>SHA256WITHRSA</c>.</summary>
    string SignatureAlgorithm { get; }

    /// <summary>Creates a factory that BouncyCastle drives to sign one structure.</summary>
    ISignatureFactory CreateSignatureFactory();
}

/// <summary>
/// <see cref="ICaSigner"/> backed by a key pair held in this process, loaded from the encrypted
/// <c>ca.key</c> file. The default, and the only implementation that can sign with the PQC
/// algorithms — remote key stores do not offer ML-DSA.
/// </summary>
public sealed class LocalKeyPairCaSigner : ICaSigner
{
    private readonly AsymmetricKeyParameter _privateKey;

    public LocalKeyPairCaSigner(AsymmetricCipherKeyPair keyPair)
    {
        PublicKey = keyPair.Public;
        _privateKey = keyPair.Private;
        SignatureAlgorithm = QertumKeyCodec.SignatureAlgorithmName(_privateKey);
    }

    public AsymmetricKeyParameter PublicKey { get; }

    public string SignatureAlgorithm { get; }

    public ISignatureFactory CreateSignatureFactory() => QertumKeyCodec.SignatureFactoryFor(_privateKey);
}
