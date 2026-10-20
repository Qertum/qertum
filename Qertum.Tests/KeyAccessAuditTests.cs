using Qertum.Services;

namespace Qertum.Tests;

public sealed class KeyAccessAuditTests
{
    [Theory]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, false, "Signing private key")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, true, "Encryption private key")]
    // Hybrid and single-certificate wording must not change.
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, false, "Private key")]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, true, "PQC private key")]
    [InlineData(CertificateKeyAlgorithm.MlDsa65, false, "Private key")]
    public void PrivateKeyDetail_NamesTheCertificateOfAPair_AndLeavesTheOthersAlone(
        CertificateKeyAlgorithm algorithm, bool secondLeg, string expected) =>
        Assert.Equal(expected, KeyAccessAudit.PrivateKeyDetail(algorithm, secondLeg));

    [Fact]
    public void PrivateKeyDetail_ForAnUnknownAlgorithm_IsThePlainWording() =>
        Assert.Equal("Private key", KeyAccessAudit.PrivateKeyDetail(null, secondLeg: false));

    [Theory]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, false, false, "PKCS#12 (signing certificate)")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, true, true, "PKCS#12 (encryption certificate) with CA chain")]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, true, false, "PKCS#12")]
    [InlineData(CertificateKeyAlgorithm.Rsa, false, true, "PKCS#12 with CA chain")]
    public void PfxDetail_NamesTheCertificateOfAPair_AndKeepsTheExistingWordingOtherwise(
        CertificateKeyAlgorithm algorithm, bool secondLeg, bool includeChain, string expected) =>
        Assert.Equal(expected, KeyAccessAudit.PfxDetail(algorithm, secondLeg, includeChain));
}
