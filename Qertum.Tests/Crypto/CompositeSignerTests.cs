using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// Sign and Verify (draft -19 §3.2, §3.3). The published signatures must verify, with and without the
/// context; a signature produced here must verify; and a composite signature must fail whenever
/// either component is damaged — that is the property that makes composite non-downgradable.
/// </summary>
public sealed class CompositeSignerTests
{
    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    [Theory]
    [MemberData(nameof(Names))]
    public void PublishedSignatureVerifies(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.True(Verify(algorithm, vector.PublicKey, [], vector.Signature));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void PublishedSignatureWithContextVerifies(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.True(Verify(algorithm, vector.PublicKey, CompositeTestVectors.Context, vector.SignatureWithContext));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void ContextIsBoundIntoTheSignature(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.False(Verify(algorithm, vector.PublicKey, CompositeTestVectors.Context, vector.Signature));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void SignatureProducedHereVerifiesUnderThePublishedKey(string name)
    {
        var (algorithm, vector) = Load(name);
        var signer = new CompositeSigner(algorithm);
        signer.Init(true, new ParametersWithRandom(CompositePrivateKey.Decode(algorithm, vector.PrivateKey), new SecureRandom()));
        signer.BlockUpdate(CompositeTestVectors.Message);

        Assert.True(Verify(algorithm, vector.PublicKey, [], signer.GenerateSignature()));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void DamagedMlDsaComponentFailsTheWholeSignature(string name)
    {
        var (algorithm, vector) = Load(name);
        var signature = vector.Signature.ToArray();
        signature[5] ^= 0x01;

        Assert.False(Verify(algorithm, vector.PublicKey, [], signature));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void DamagedTraditionalComponentFailsTheWholeSignature(string name)
    {
        var (algorithm, vector) = Load(name);
        var signature = vector.Signature.ToArray();
        signature[^3] ^= 0x01;

        Assert.False(Verify(algorithm, vector.PublicKey, [], signature));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void MlDsaComponentAloneDoesNotVerify(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.False(Verify(algorithm, vector.PublicKey, [], vector.Signature[..algorithm.MlDsaSignatureLength]));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void TrailingBytesFailTheSignature(string name)
    {
        var (algorithm, vector) = Load(name);

        Assert.False(Verify(algorithm, vector.PublicKey, [], [.. vector.Signature, 0x00]));
    }

    [Fact]
    public void KeyOfAnotherAlgorithmIsRefused()
    {
        var (_, vector) = Load("MLDSA65-ECDSA-P256-SHA512");
        var key = CompositePublicKey.Decode(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!, vector.PublicKey);
        var other = new CompositeSigner(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P384-SHA512")!);

        Assert.Throws<ArgumentException>(() => other.Init(false, key));
    }

    [Fact]
    public void ContextLongerThan255BytesIsRefused() =>
        Assert.Throws<ArgumentException>(() => new CompositeSigner(CompositeAlgorithms.All[0], new byte[256]));

    private static bool Verify(CompositeAlgorithm algorithm, byte[] publicKey, byte[] context, byte[] signature)
    {
        var verifier = new CompositeSigner(algorithm, context);
        verifier.Init(false, CompositePublicKey.Decode(algorithm, publicKey));
        verifier.BlockUpdate(CompositeTestVectors.Message);
        return verifier.VerifySignature(signature);
    }

    private static (CompositeAlgorithm Algorithm, CompositeTestVectors.Vector Vector) Load(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        return (algorithm, CompositeTestVectors.For(algorithm));
    }
}
