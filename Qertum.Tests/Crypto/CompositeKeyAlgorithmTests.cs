using Org.BouncyCastle.Asn1.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// The 18 composite <see cref="CertificateKeyAlgorithm"/> values and the Services registry are two
/// halves of one fact: the enum is what is stored and sent, the registry is what signs. These tests
/// keep them joined, and pin the parts of the system that choose behaviour by family.
/// </summary>
public sealed class CompositeKeyAlgorithmTests
{
    private static IEnumerable<CertificateKeyAlgorithm> CompositeValues =>
        Enum.GetValues<CertificateKeyAlgorithm>().Where(a => a.GetFamily() == AlgorithmFamily.Composite);

    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    [Fact]
    public void EveryRegistryRowHasExactlyOneEnumValueAndBack()
    {
        Assert.Equal(18, CompositeValues.Count());
        Assert.Equal(
            CompositeAlgorithms.All.Select(a => a.Name).Order(StringComparer.Ordinal),
            CompositeValues.Select(a => a.ToCanonicalString()).Order(StringComparer.Ordinal));
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void CanonicalStringRoundTripsAndParsesCaseInsensitively(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;
        var value = algorithm.ToKeyAlgorithm();

        Assert.Equal(name, value.ToCanonicalString());
        Assert.Equal(value, CertificateKeyAlgorithmExtensions.Parse(name.ToLowerInvariant()));
        Assert.Same(algorithm, CompositeAlgorithms.For(value));
        Assert.Equal(AlgorithmFamily.Composite, value.GetFamily());
    }

    [Fact]
    public void ContractsOidTableMatchesTheRegistry()
    {
        Assert.Equal(
            CompositeAlgorithms.All.Select(a => (a.Oid.Id, a.ToKeyAlgorithm())).OrderBy(p => p.Id, StringComparer.Ordinal),
            CertificateKeyAlgorithmExtensions.CompositeAlgorithmsByOid.Select(p => (p.Key, p.Value)).OrderBy(p => p.Key, StringComparer.Ordinal));
    }

    [Fact]
    public void NewMembersKeepEveryExistingOrdinal()
    {
        // Stored rows persist the canonical string, but ordinals leak into anything that casts.
        Assert.Equal(9, (int)CertificateKeyAlgorithm.SlhDsaSha2128f);
        Assert.Equal(10, (int)CertificateKeyAlgorithm.MlDsa44Rsa2048PssSha256);
        Assert.Equal(27, (int)CertificateKeyAlgorithm.MlDsa87EcdsaP521Sha512);
    }

    [Fact]
    public void ForRefusesANonCompositeValue() =>
        Assert.Throws<ArgumentException>(() => CompositeAlgorithms.For(CertificateKeyAlgorithm.MlDsa65));

    [Theory]
    [MemberData(nameof(Names))]
    public void StrategyFactoryGivesACompositeStrategy(string name)
    {
        var value = CompositeAlgorithms.FindByName(name)!.ToKeyAlgorithm();

        var strategy = AlgorithmStrategyFactory.CreateIssuer(value);

        Assert.Equal(name, strategy.CaSignatureAlgorithm);
    }

    [Fact]
    public void StrategyFromACompositePrivateKeyIsNotTheRsaDefault()
    {
        var keys = CompositeKeyPairGenerator.Generate(
            CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!, new Org.BouncyCastle.Security.SecureRandom());

        Assert.Equal("MLDSA65-ECDSA-P256-SHA512", AlgorithmStrategyFactory.CreateFromPrivateKey(keys.Private).CaSignatureAlgorithm);
    }

    [Fact]
    public void CompositeKeyUsageIsSignatureOnly()
    {
        var strategy = AlgorithmStrategyFactory.Create(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512);

        var bits = strategy.BuildKeyUsageBits(["DigitalSignature", "KeyEncipherment", "DataEncipherment", "KeyAgreement"]);

        Assert.Equal(KeyUsage.DigitalSignature, bits);
        Assert.Equal(KeyUsage.DigitalSignature, strategy.BuildKeyUsageBits([]));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512)]
    [InlineData(CertificateKeyAlgorithm.MlDsa87Ed448Shake256)]
    public void PqcOnlyPolicyAdmitsComposite(CertificateKeyAlgorithm algorithm) =>
        Assert.True(PqcStageEvaluator.IsCompliant(algorithm));
}
