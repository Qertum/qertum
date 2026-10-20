using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests.Secrets;

public sealed class LocalFileKeySecretProtectorTests : IDisposable
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "secret-storage-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dataDir)) Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void ProtectThenUnprotect_ReturnsTheOriginalBytes()
    {
        var protector = new LocalFileKeySecretProtector(_dataDir);
        var plaintext = "hello secret"u8.ToArray();

        var ciphertext = protector.Protect(plaintext);
        var roundTripped = protector.Unprotect(ciphertext);

        Assert.Equal(plaintext, roundTripped);
        Assert.NotEqual(plaintext, ciphertext);
    }

    [Fact]
    public void FirstUse_WritesAKeyFileSeparateFromTheDataDirectory()
    {
        _ = new LocalFileKeySecretProtector(_dataDir).Protect("x"u8.ToArray());

        var keyPath = Path.Combine(_dataDir, "secret-storage", "local.key");
        Assert.True(File.Exists(keyPath));
    }

    [Fact]
    public void TwoInstancesOverTheSameDirectory_ShareTheSameKey()
    {
        var first = new LocalFileKeySecretProtector(_dataDir);
        var ciphertext = first.Protect("shared"u8.ToArray());

        var second = new LocalFileKeySecretProtector(_dataDir);
        var roundTripped = second.Unprotect(ciphertext);

        Assert.Equal("shared"u8.ToArray(), roundTripped);
    }
}
