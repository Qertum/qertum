using System.Xml.Linq;
using Qertum.ServiceDefaults.Secrets;
using Qertum.Services.DataProtection;

namespace Qertum.Tests.DataProtection;

public sealed class SecretProtectorXmlEncryptorTests : IDisposable
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "xml-encryptor-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dataDir)) Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void EncryptThenDecrypt_ReturnsAnEquivalentElement()
    {
        var protector = new LocalFileKeySecretProtector(_dataDir);
        var encryptor = new SecretProtectorXmlEncryptor(protector);

        var original = new XElement("key", new XElement("value", "super-secret"));

        var encryptedInfo = encryptor.Encrypt(original);
        var decrypted = encryptor.Decrypt(encryptedInfo.EncryptedElement);

        Assert.Equal(original.ToString(), decrypted.ToString());
    }

    [Fact]
    public void Encrypt_ProducesDifferentBytesThanThePlaintext()
    {
        var protector = new LocalFileKeySecretProtector(_dataDir);
        var encryptor = new SecretProtectorXmlEncryptor(protector);

        var original = new XElement("key", "plaintext-marker-xyz");
        var encryptedInfo = encryptor.Encrypt(original);

        Assert.DoesNotContain("plaintext-marker-xyz", encryptedInfo.EncryptedElement.ToString());
    }
}
