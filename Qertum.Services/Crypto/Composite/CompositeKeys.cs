using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// A composite ML-DSA public key: an ML-DSA key and a traditional key under one OID. Subclasses
/// <see cref="AsymmetricKeyParameter"/> so it passes through <c>ICaSigner</c>, key pairs and
/// strategies unchanged; only <c>QertumKeyCodec</c> turns it into or out of bytes.
/// </summary>
public sealed class CompositePublicKey : AsymmetricKeyParameter
{
    public CompositePublicKey(CompositeAlgorithm algorithm, MLDsaPublicKeyParameters mlDsa, AsymmetricKeyParameter traditional)
        : base(false)
    {
        if (mlDsa.Parameters != algorithm.MlDsa)
            throw new ArgumentException($"{algorithm.Name} needs an {algorithm.MlDsa.Name} key.", nameof(mlDsa));
        Algorithm = algorithm;
        MlDsa = mlDsa;
        Traditional = traditional;
    }

    public CompositeAlgorithm Algorithm { get; }
    public MLDsaPublicKeyParameters MlDsa { get; }
    public AsymmetricKeyParameter Traditional { get; }

    /// <summary>§4.1: <c>mldsaPK || tradPK</c>, with no length prefix.</summary>
    public byte[] GetEncoded() => [.. MlDsa.GetEncoded(), .. CompositeTraditionalKeys.EncodePublic(Algorithm, Traditional)];

    /// <summary>Splits at the fixed ML-DSA length. Throws <see cref="ArgumentException"/> on anything malformed.</summary>
    public static CompositePublicKey Decode(CompositeAlgorithm algorithm, ReadOnlySpan<byte> encoded)
    {
        var split = algorithm.MlDsaPublicKeyLength;
        if (encoded.Length <= split)
            throw new ArgumentException($"A {algorithm.Name} public key is longer than {split} bytes.", nameof(encoded));
        try
        {
            return new CompositePublicKey(
                algorithm,
                MLDsaPublicKeyParameters.FromEncoding(algorithm.MlDsa, encoded[..split].ToArray()),
                CompositeTraditionalKeys.DecodePublic(algorithm, encoded[split..].ToArray()));
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new ArgumentException($"The {algorithm.Name} public key is malformed.", nameof(encoded), ex);
        }
    }
}

/// <summary>
/// A composite ML-DSA private key. The ML-DSA half is always held in seed form, because §4.2
/// serializes the 32-byte seed, not the expanded key.
/// </summary>
public sealed class CompositePrivateKey : AsymmetricKeyParameter
{
    private const int SeedLength = 32;

    public CompositePrivateKey(CompositeAlgorithm algorithm, MLDsaPrivateKeyParameters mlDsa, AsymmetricKeyParameter traditional)
        : base(true)
    {
        if (mlDsa.Parameters != algorithm.MlDsa)
            throw new ArgumentException($"{algorithm.Name} needs an {algorithm.MlDsa.Name} key.", nameof(mlDsa));
        if (mlDsa.GetSeed() is not { Length: SeedLength })
            throw new ArgumentException("A composite private key needs the ML-DSA seed (§4.2).", nameof(mlDsa));
        Algorithm = algorithm;
        MlDsa = mlDsa;
        Traditional = traditional;
    }

    public CompositeAlgorithm Algorithm { get; }
    public MLDsaPrivateKeyParameters MlDsa { get; }
    public AsymmetricKeyParameter Traditional { get; }

    public CompositePublicKey PublicKey =>
        new(Algorithm, MlDsa.GetPublicKey(), CompositeTraditionalKeys.PublicFromPrivate(Traditional));

    /// <summary>§4.2: <c>mldsaSeed || tradSK</c>.</summary>
    public byte[] GetEncoded() => [.. MlDsa.GetSeed(), .. CompositeTraditionalKeys.EncodePrivate(Algorithm, Traditional)];

    public static CompositePrivateKey Decode(CompositeAlgorithm algorithm, ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length <= SeedLength)
            throw new ArgumentException($"A {algorithm.Name} private key is longer than {SeedLength} bytes.", nameof(encoded));
        try
        {
            return new CompositePrivateKey(
                algorithm,
                MLDsaPrivateKeyParameters.FromSeed(algorithm.MlDsa, encoded[..SeedLength].ToArray()),
                CompositeTraditionalKeys.DecodePrivate(algorithm, encoded[SeedLength..].ToArray()));
        }
        catch (Exception ex) when (ex is not ArgumentException)
        {
            throw new ArgumentException($"The {algorithm.Name} private key is malformed.", nameof(encoded), ex);
        }
    }
}
