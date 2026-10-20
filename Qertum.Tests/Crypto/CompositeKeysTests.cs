using Org.BouncyCastle.Crypto.Parameters;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// The draft's §4 encodings, checked against the published keys: every vector key must decode and
/// re-encode to the exact same bytes, and the public key derived from the private key must equal
/// the published one.
/// </summary>
public sealed class CompositeKeysTests
{
    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    [Theory]
    [MemberData(nameof(Names))]
    public void PublicKeyRoundTripsTheVector(string name)
    {
        var (algorithm, vector) = Load(name);

        var key = CompositePublicKey.Decode(algorithm, vector.PublicKey);

        Assert.Equal(vector.PublicKey, key.GetEncoded());
        Assert.Same(algorithm, key.Algorithm);
        Assert.False(key.IsPrivate);
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void PrivateKeyRoundTripsTheVector(string name)
    {
        var (algorithm, vector) = Load(name);

        var key = CompositePrivateKey.Decode(algorithm, vector.PrivateKey);

        Assert.Equal(vector.PrivateKey, key.GetEncoded());
        Assert.True(key.IsPrivate);
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void PublicKeyDerivedFromThePrivateKeyMatchesTheVector(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.Equal(vector.PublicKey, CompositePrivateKey.Decode(algorithm, vector.PrivateKey).PublicKey.GetEncoded());
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void TooShortInputIsRejected(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.Throws<ArgumentException>(() => CompositePublicKey.Decode(algorithm, vector.PublicKey.AsSpan(0, algorithm.MlDsaPublicKeyLength)));
        Assert.Throws<ArgumentException>(() => CompositePrivateKey.Decode(algorithm, vector.PrivateKey.AsSpan(0, 32)));
    }

    [Fact]
    public void RsaKeyOfTheWrongSizeIsRejected()
    {
        // Same ML-DSA level, RSA-3072 key presented as RSA-4096.
        var rsa3072 = Load("MLDSA65-RSA3072-PSS-SHA512").Vector;
        var rsa4096 = CompositeAlgorithms.FindByName("MLDSA65-RSA4096-PSS-SHA512")!;

        Assert.Throws<ArgumentException>(() => CompositePublicKey.Decode(rsa4096, rsa3072.PublicKey));
        Assert.Throws<ArgumentException>(() => CompositePrivateKey.Decode(rsa4096, rsa3072.PrivateKey));
    }

    [Fact]
    public void EcPointNotOnTheCurveIsRejected()
    {
        // A P-256 point presented as a P-384 key.
        var p256 = Load("MLDSA65-ECDSA-P256-SHA512").Vector;
        var p384 = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P384-SHA512")!;

        Assert.Throws<ArgumentException>(() => CompositePublicKey.Decode(p384, p256.PublicKey));
    }

    [Fact]
    public void TrailingBytesAfterAnEdDsaKeyAreRejected()
    {
        var (algorithm, vector) = Load("MLDSA65-Ed25519-SHA512");

        Assert.Throws<ArgumentException>(() => CompositePublicKey.Decode(algorithm, [.. vector.PublicKey, 0]));
    }

    [Fact]
    public void MlDsaKeyOfTheWrongParameterSetIsRejected()
    {
        var mlDsa87 = CompositeAlgorithms.FindByName("MLDSA87-ECDSA-P384-SHA512")!;
        var mlDsa65Key = CompositePrivateKey.Decode(
            CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P384-SHA512")!,
            Load("MLDSA65-ECDSA-P384-SHA512").Vector.PrivateKey);

        Assert.Throws<ArgumentException>(() => new CompositePrivateKey(mlDsa87, mlDsa65Key.MlDsa, mlDsa65Key.Traditional));
    }

    [Fact]
    public void PrivateKeyWithoutAnMlDsaSeedIsRejected()
    {
        var algorithm = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!;
        var withSeed = CompositePrivateKey.Decode(algorithm, Load(algorithm.Name).Vector.PrivateKey);
        var expandedOnly = MLDsaPrivateKeyParameters.FromEncoding(algorithm.MlDsa, withSeed.MlDsa.GetEncoded());

        Assert.Throws<ArgumentException>(() => new CompositePrivateKey(algorithm, expandedOnly, withSeed.Traditional));
    }

    private static (CompositeAlgorithm Algorithm, CompositeTestVectors.Vector Vector) Load(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        return (algorithm, CompositeTestVectors.For(algorithm));
    }
}
