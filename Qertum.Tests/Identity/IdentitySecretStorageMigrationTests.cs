using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Services;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests.Identity;

public sealed class IdentitySecretStorageMigrationTests : IDisposable
{
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), $"idp-secrets-{Guid.NewGuid():N}");
    private string KeysDir => Path.Combine(_dataPath, "keys");

    public IdentitySecretStorageMigrationTests() => Directory.CreateDirectory(KeysDir);

    public void Dispose()
    {
        if (Directory.Exists(_dataPath)) Directory.Delete(_dataPath, recursive: true);
    }

    [Fact]
    public void NoConfiguredProvider_LeavesEverythingUntouched()
    {
        var file = WriteKeyFile("signing-1.pfx", Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]));

        var change = IdentitySecretStorageMigration.Apply(_dataPath, configured: null, Fake);

        Assert.Null(change);
        Assert.Equal(Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]), File.ReadAllBytes(file));
        Assert.False(File.Exists(Path.Combine(_dataPath, "secret-storage.json")));
    }

    [Fact]
    public void ConfiguredProviderAlreadyStored_IsANoOp()
    {
        SecretStorageConfig.Write(_dataPath, SecretStorageProvider.LocalTpm);
        var file = WriteKeyFile("signing-1.pfx", Marked(SecretStorageProvider.LocalTpm, [1, 2, 3]));

        var change = IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm, Fake);

        Assert.Null(change);
        Assert.Equal(Marked(SecretStorageProvider.LocalTpm, [1, 2, 3]), File.ReadAllBytes(file));
    }

    [Fact]
    public void ChangedProvider_ReencryptsEveryKeyFileAndRecordsTheProvider()
    {
        var signing = WriteKeyFile("signing-1.pfx", Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]));
        var encryption = WriteKeyFile("encryption-1.pfx", Marked(SecretStorageProvider.LocalFileKey, [4, 5]));

        var change = IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm, Fake);

        Assert.Equal(new SecretStorageChange(SecretStorageProvider.LocalFileKey, SecretStorageProvider.LocalTpm), change);
        Assert.Equal(Marked(SecretStorageProvider.LocalTpm, [1, 2, 3]), File.ReadAllBytes(signing));
        Assert.Equal(Marked(SecretStorageProvider.LocalTpm, [4, 5]), File.ReadAllBytes(encryption));
        Assert.Equal(SecretStorageProvider.LocalTpm, SecretStorageConfig.Read(_dataPath));
        Assert.False(Directory.Exists(KeysDir + ".migrating"));
        Assert.False(Directory.Exists(KeysDir + ".bak"));
    }

    [Fact]
    public void LegacyPlaintextKeyFile_IsProtectedUnderTheTarget()
    {
        // IdentityCertificateStore adopts a file the current provider cannot unprotect as plaintext
        // PKCS#12; the migration must carry such a file over the same way, not drop it.
        var legacy = WriteKeyFile("signing-legacy.pfx", [9, 9, 9]);

        IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm, Fake);

        Assert.Equal(Marked(SecretStorageProvider.LocalTpm, [9, 9, 9]), File.ReadAllBytes(legacy));
    }

    [Fact]
    public void FailureWhileReencrypting_LeavesKeysAndProviderUnchanged()
    {
        var file = WriteKeyFile("signing-1.pfx", Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]));

        var ex = Assert.Throws<InvalidOperationException>(() =>
            IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm,
                provider => provider == SecretStorageProvider.LocalTpm ? new FailingProtector() : Fake(provider)));

        Assert.Contains("LocalTpm", ex.Message);
        Assert.Equal(Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]), File.ReadAllBytes(file));
        Assert.Equal(SecretStorageProvider.LocalFileKey, SecretStorageConfig.Read(_dataPath));
        Assert.False(Directory.Exists(KeysDir + ".migrating"));
    }

    [Fact]
    public void NoKeysDirectory_StillRecordsTheProvider()
    {
        Directory.Delete(KeysDir);

        var change = IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm, Fake);

        Assert.NotNull(change);
        Assert.Equal(SecretStorageProvider.LocalTpm, SecretStorageConfig.Read(_dataPath));
    }

    [Fact]
    public void InterruptedSwap_IsRecoveredFromTheBackupBeforeMigrating()
    {
        // A crash between the two directory renames leaves keys/ missing and keys.bak holding the
        // only copy. The next start must put it back rather than treat the key set as empty.
        WriteKeyFile("signing-1.pfx", Marked(SecretStorageProvider.LocalFileKey, [1, 2, 3]));
        Directory.Move(KeysDir, KeysDir + ".bak");

        IdentitySecretStorageMigration.Apply(_dataPath, SecretStorageProvider.LocalTpm, Fake);

        Assert.Equal(Marked(SecretStorageProvider.LocalTpm, [1, 2, 3]),
            File.ReadAllBytes(Path.Combine(KeysDir, "signing-1.pfx")));
        Assert.False(Directory.Exists(KeysDir + ".bak"));
    }

    [Fact]
    public void Options_BindTheConfiguredProvider()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["IdentityService:SecretStorageProvider"] = "LocalTpm"
        }).Build();
        var options = new IdentityServiceOptions();
        configuration.GetSection(IdentityServiceOptions.SectionName).Bind(options);

        Assert.Equal(SecretStorageProvider.LocalTpm, options.SecretStorageProvider);
    }

    [Fact]
    public void Options_RefuseTheCloudStub()
    {
        var options = new IdentityServiceOptions { SecretStorageProvider = SecretStorageProvider.CloudStub };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: true));

        Assert.Contains("IdentityService:SecretStorageProvider", ex.Message);
    }

    private string WriteKeyFile(string name, byte[] contents)
    {
        var path = Path.Combine(KeysDir, name);
        File.WriteAllBytes(path, contents);
        return path;
    }

    private static byte[] Marked(SecretStorageProvider provider, byte[] plaintext) =>
        [(byte)(0xA0 + (int)provider), .. plaintext];

    private static ISecretProtector Fake(SecretStorageProvider provider) => new MarkingProtector(provider);

    /// <summary>Prefixes a per-provider marker byte, so a test can tell which provider wrote a file.</summary>
    private sealed class MarkingProtector(SecretStorageProvider provider) : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => Marked(provider, plaintext);

        public byte[] Unprotect(byte[] ciphertext) =>
            ciphertext.Length > 0 && ciphertext[0] == (byte)(0xA0 + (int)provider)
                ? ciphertext[1..]
                : throw new CryptographicException("Not protected by this provider.");
    }

    private sealed class FailingProtector : ISecretProtector
    {
        public byte[] Protect(byte[] plaintext) => throw new CryptographicException("TPM unavailable.");
        public byte[] Unprotect(byte[] ciphertext) => throw new CryptographicException("TPM unavailable.");
    }
}
