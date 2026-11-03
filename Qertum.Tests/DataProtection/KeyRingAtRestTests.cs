using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Qertum.ServiceDefaults.Secrets;
using Qertum.Services.DataProtection;

namespace Qertum.Tests.DataProtection;

/// <summary>
/// The CA's Data Protection key ring protects the CA key, issued private keys and webhook secrets, and the secret-storage
/// provider (file key or TPM) is what protects the key ring on disk. The provider was registered where Data Protection
/// never looks (a DI singleton instead of <c>KeyManagementOptions.XmlEncryptor</c>), so every key file held its master
/// key in plain text. Each test builds the pipeline as a separate process would: its own container over shared files.
/// </summary>
public sealed class KeyRingAtRestTests : IDisposable
{
    private readonly string _dataDir = Directory.CreateTempSubdirectory("qertum-keyring-").FullName;
    private string KeysDir => Path.Combine(_dataDir, "DataProtection-Keys");

    public void Dispose()
    {
        try { Directory.Delete(_dataDir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private ServiceProvider Process(ISecretProtector? protector)
    {
        var services = new ServiceCollection();
        var dp = services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(KeysDir)).SetApplicationName("Qertum");
        if (protector is not null)
            dp.ProtectKeysWithSecretProtector(protector);
        return services.BuildServiceProvider();
    }

    private static string Protect(ServiceProvider process, string value) =>
        process.GetRequiredService<IDataProtectionProvider>().CreateProtector("keyring-test").Protect(value);

    private static string Unprotect(ServiceProvider process, string payload) =>
        process.GetRequiredService<IDataProtectionProvider>().CreateProtector("keyring-test").Unprotect(payload);

    private string[] KeyFiles() => Directory.GetFiles(KeysDir, "key-*.xml").Select(File.ReadAllText).ToArray();

    [Fact]
    public void KeyFiles_AreEncryptedWithTheSecretProtector_AndAnotherProcessReadsThem()
    {
        string payload;
        using (var writer = Process(SecretProtectorFactory.Create(_dataDir)))
            payload = Protect(writer, "ca-key-material");

        var files = KeyFiles();
        Assert.NotEmpty(files);
        Assert.All(files, xml =>
        {
            Assert.Contains("encryptedSecret", xml);
            Assert.DoesNotContain("requiresEncryption", xml);
        });

        using var reader = Process(SecretProtectorFactory.Create(_dataDir));
        Assert.Equal("ca-key-material", Unprotect(reader, payload));
    }

    [Fact]
    public void PlainKeyFilesFromAnOlderVersion_AreEncryptedInPlace_AndStillDecrypt()
    {
        string payload;
        using (var old = Process(protector: null))
            payload = Protect(old, "written-by-rc3");
        Assert.All(KeyFiles(), xml => Assert.Contains("requiresEncryption", xml));

        var rewritten = KeyRingAtRest.EncryptPlainKeyFiles(KeysDir, SecretProtectorFactory.Create(_dataDir));

        Assert.Equal(KeyFiles().Length, rewritten);
        Assert.All(KeyFiles(), xml => Assert.DoesNotContain("requiresEncryption", xml));
        Assert.Equal(0, KeyRingAtRest.EncryptPlainKeyFiles(KeysDir, SecretProtectorFactory.Create(_dataDir)));
        using var reader = Process(SecretProtectorFactory.Create(_dataDir));
        Assert.Equal("written-by-rc3", Unprotect(reader, payload));
    }

    [Fact]
    public void Migration_LeavesAKeyRingAFreshProcessCanRead()
    {
        string payload;
        using (var before = Process(SecretProtectorFactory.Create(_dataDir)))
            payload = Protect(before, "survives-the-migration");

        KeyRingAtRest.Migrate(_dataDir, SecretStorageProvider.LocalFileKey);

        Assert.False(Directory.Exists(Path.Combine(_dataDir, "secret-storage.migrating")));
        Assert.False(Directory.Exists(Path.Combine(_dataDir, "DataProtection-Keys.migrating")));
        using var after = Process(SecretProtectorFactory.Create(_dataDir));
        Assert.Equal("survives-the-migration", Unprotect(after, payload));
    }

    [Fact]
    public void Migration_EncryptsKeyFilesThatWereStillPlain()
    {
        string payload;
        using (var old = Process(protector: null))
            payload = Protect(old, "plain-before");

        KeyRingAtRest.Migrate(_dataDir, SecretStorageProvider.LocalFileKey);

        Assert.All(KeyFiles(), xml => Assert.DoesNotContain("requiresEncryption", xml));
        using var after = Process(SecretProtectorFactory.Create(_dataDir));
        Assert.Equal("plain-before", Unprotect(after, payload));
    }
}
