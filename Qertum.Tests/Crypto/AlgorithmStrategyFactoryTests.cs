using Qertum.Services;
using Qertum.Services.Crypto;

namespace Qertum.Tests.Crypto;

/// <summary>
/// <see cref="AlgorithmStrategyFactory.CreateIssuer"/> is the one place that decides which
/// algorithms may hold a CA key. Before it existed, root eligibility fell out of
/// <c>Create</c> throwing, so registering a subject-key strategy made an algorithm a root as a side
/// effect — which is exactly what an ML-KEM strategy would have done.
/// </summary>
public sealed class AlgorithmStrategyFactoryTests
{
    // Pinned by hand: widening root eligibility must be a deliberate edit to this list.
    private static readonly CertificateKeyAlgorithm[] NonCompositeIssuers =
    [
        CertificateKeyAlgorithm.Rsa,
        CertificateKeyAlgorithm.EcdsaP256,
        CertificateKeyAlgorithm.EcdsaP384,
        CertificateKeyAlgorithm.MlDsa44,
        CertificateKeyAlgorithm.MlDsa65,
        CertificateKeyAlgorithm.MlDsa87,
        CertificateKeyAlgorithm.SlhDsaSha2128s,
        CertificateKeyAlgorithm.SlhDsaSha2128f,
    ];

    private static bool IsIssuer(CertificateKeyAlgorithm algorithm)
    {
        try
        {
            AlgorithmStrategyFactory.CreateIssuer(algorithm);
            return true;
        }
        catch (NotSupportedException)
        {
            return false;
        }
    }

    [Fact]
    public void CreateIssuer_AcceptsExactlyThePinnedSetPlusEveryComposite()
    {
        var expected = NonCompositeIssuers
            .Concat(Enum.GetValues<CertificateKeyAlgorithm>().Where(a => a.GetFamily() == AlgorithmFamily.Composite))
            .Order();

        Assert.Equal(expected, Enum.GetValues<CertificateKeyAlgorithm>().Where(IsIssuer).Order());
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa44MlKem512)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa87MlKem1024)]
    [InlineData(CertificateKeyAlgorithm.MlKem512)]
    [InlineData(CertificateKeyAlgorithm.MlKem768)]
    [InlineData(CertificateKeyAlgorithm.MlKem1024)]
    public void CreateIssuer_RefusesPairedAndKemAlgorithms(CertificateKeyAlgorithm algorithm) =>
        Assert.Throws<NotSupportedException>(() => AlgorithmStrategyFactory.CreateIssuer(algorithm));

    // Every value that is not paired has a subject-key strategy, issuer or not.
    [Fact]
    public void Create_GivesASubjectKeyStrategyForEveryNonPairedAlgorithm()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>().Where(a => !a.IsPaired()))
            Assert.NotNull(AlgorithmStrategyFactory.Create(algorithm));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768)]
    public void Create_RefusesPairedAlgorithms_BecauseAPairIsTwoCertificates(CertificateKeyAlgorithm algorithm) =>
        Assert.Throws<NotSupportedException>(() => AlgorithmStrategyFactory.Create(algorithm));
}
