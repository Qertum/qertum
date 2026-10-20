using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

public sealed class EncryptedPrivateKeyTests
{
    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP384)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2128f)]
    public void RoundTrips_WithTheRightPassphrase(CertificateKeyAlgorithm algorithm)
    {
        var pair = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());

        var pem = QertumKeyCodec.WriteEncryptedPrivateKeyPem(pair.Private, "correct horse");
        var back = QertumKeyCodec.ReadEncryptedPrivateKeyPem(pem, "correct horse");

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.True(QertumKeyCodec.IsMatchingPair(back, pair.Public));
    }

    [Fact]
    public void RoundTrips_ACompositeKey()
    {
        var pair = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!, new SecureRandom());

        var back = QertumKeyCodec.ReadEncryptedPrivateKeyPem(QertumKeyCodec.WriteEncryptedPrivateKeyPem(pair.Private, "pw"), "pw");

        Assert.True(QertumKeyCodec.IsMatchingPair(back, pair.Public));
    }

    [Fact]
    public void WrongPassphrase_IsAnArgumentException()
    {
        var pair = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom());
        var pem = QertumKeyCodec.WriteEncryptedPrivateKeyPem(pair.Private, "right");

        Assert.Throws<ArgumentException>(() => QertumKeyCodec.ReadEncryptedPrivateKeyPem(pem, "wrong"));
    }

    [Fact]
    public void OpenSsl_ReadsTheEncryptedRsaKey()
    {
        var openSsl = OpenSslTool.Find();
        if (openSsl is null) Assert.Skip("OpenSSL 3 is not installed.");
        var pair = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.Rsa).GenerateCaKeyPair(new SecureRandom());
        var path = Path.Combine(Path.GetTempPath(), $"enc-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, QertumKeyCodec.WriteEncryptedPrivateKeyPem(pair.Private, "pw"));
        try
        {
            var (exitCode, output) = OpenSslTool.Run(openSsl!, $"pkey -in {path} -passin pass:pw -noout");
            Assert.True(exitCode == 0, output);
        }
        finally { File.Delete(path); }
    }
}
