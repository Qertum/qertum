using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Crypto;

namespace Qertum.Tests;

/// <summary>
/// ML-KEM (FIPS 203) subject keys: 512, 768 and 1024. A KEM key establishes a shared secret and
/// can never sign, which is what every test below guards in one form or another.
/// </summary>
public sealed class MlKemTests
{
    public static TheoryData<string> Sets => new() { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };

    private static CertificateKeyAlgorithm Algorithm(string canonical) =>
        CertificateKeyAlgorithmExtensions.Parse(canonical)
        ?? throw new InvalidOperationException($"{canonical} is not a recognised algorithm.");

    [Theory]
    [MemberData(nameof(Sets))]
    public void Parse_RoundTripsEachSetThroughItsCanonicalString(string canonical)
    {
        Assert.Equal(canonical, Algorithm(canonical).ToCanonicalString());
        Assert.Equal(Algorithm(canonical), CertificateKeyAlgorithmExtensions.Parse(canonical.ToLowerInvariant()));
    }

    [Theory]
    [MemberData(nameof(Sets))]
    public void EachSet_BelongsToTheKemFamilyAndCannotSign(string canonical)
    {
        Assert.Equal(AlgorithmFamily.Kem, Algorithm(canonical).GetFamily());
        Assert.False(Algorithm(canonical).CanSign());
    }

    [Fact]
    public void CanSign_IsFalseExactlyForTheKemAndPairFamilies()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
            Assert.Equal(algorithm.GetFamily() is not (AlgorithmFamily.Kem or AlgorithmFamily.Pair), algorithm.CanSign());
    }

    // Appended after the last composite value: persisted rows and the JSON converter use the
    // canonical string, but nothing may rely on a moved ordinal either.
    [Fact]
    public void TheNewValues_AreAppendedSoNoExistingOrdinalMoves()
    {
        Assert.Equal(27, (int)CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512);
        Assert.Equal(28, (int)Algorithm("ML-KEM-512"));
        Assert.Equal(29, (int)Algorithm("ML-KEM-768"));
        Assert.Equal(30, (int)Algorithm("ML-KEM-1024"));
        Assert.Equal(5, (int)AlgorithmFamily.Kem);
    }

    private static MLKemParameters ParametersOf(string canonical) => canonical switch
    {
        "ML-KEM-512" => MLKemParameters.ml_kem_512,
        "ML-KEM-768" => MLKemParameters.ml_kem_768,
        "ML-KEM-1024" => MLKemParameters.ml_kem_1024,
        _ => throw new ArgumentOutOfRangeException(nameof(canonical))
    };

    // Three sets share one strategy; a defaulting switch would be invisible by label alone.
    [Theory]
    [MemberData(nameof(Sets))]
    public void GenerateLeafKeyPair_UsesTheSetItIsNamedFor(string canonical)
    {
        var keyPair = AlgorithmStrategyFactory.Create(Algorithm(canonical)).GenerateLeafKeyPair(new SecureRandom());

        var publicKey = Assert.IsType<MLKemPublicKeyParameters>(keyPair.Public);
        Assert.Equal(ParametersOf(canonical), publicKey.Parameters);
    }

    [Theory]
    [MemberData(nameof(Sets))]
    public void BuildKeyUsageBits_IsKeyEnciphermentWhateverTheTemplateAsksFor(string canonical)
    {
        var strategy = AlgorithmStrategyFactory.Create(Algorithm(canonical));

        Assert.Equal(KeyUsage.KeyEncipherment, strategy.BuildKeyUsageBits([]));
        Assert.Equal(KeyUsage.KeyEncipherment, strategy.BuildKeyUsageBits(
            ["DigitalSignature", "NonRepudiation", "KeyEncipherment", "DataEncipherment", "KeyAgreement", "KeyCertSign", "CrlSign"]));
    }

    [Theory]
    [MemberData(nameof(Sets))]
    public void CreateFromPrivateKey_RefusesAnMlKemKeyRatherThanCallingItRsa(string canonical)
    {
        var keyPair = AlgorithmStrategyFactory.Create(Algorithm(canonical)).GenerateLeafKeyPair(new SecureRandom());

        Assert.Throws<NotSupportedException>(() => AlgorithmStrategyFactory.CreateFromPrivateKey(keyPair.Private));
    }

    // The one gate ACME finalize and both EST routes share: a CSR naming a KEM key never reaches
    // detection, because its self-signature cannot verify.
    [Fact]
    public void DetectAlgorithmFromCsr_NeverReturnsForAnMlKemKeyedCsr()
    {
        var csr = TestCsrBuilder.BuildMlKemKeyedBase64Url("kem.example.test");

        Assert.ThrowsAny<Exception>(() => CertificateGenerator.DetectAlgorithmFromCsr(csr));
        Assert.ThrowsAny<Exception>(() => Qertum.Services.Est.EstCsrHelper.ExtractIdentity(csr));
    }
}
