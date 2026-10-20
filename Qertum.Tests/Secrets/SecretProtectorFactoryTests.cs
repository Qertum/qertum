using Qertum.ServiceDefaults.Secrets;

namespace Qertum.Tests.Secrets;

public sealed class SecretProtectorFactoryTests : IDisposable
{
    private readonly string _dataDir = Path.Combine(Path.GetTempPath(), "secret-storage-factory-test-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dataDir)) Directory.Delete(_dataDir, recursive: true);
    }

    [Fact]
    public void NoConfigFile_DefaultsToLocalFileKey()
    {
        var protector = SecretProtectorFactory.Create(_dataDir);
        Assert.IsType<LocalFileKeySecretProtector>(protector);
    }

    [Fact]
    public void ConfigFileNamesCloudStub_ReturnsTheStub()
    {
        SecretStorageConfig.Write(_dataDir, SecretStorageProvider.CloudStub);

        var protector = SecretProtectorFactory.Create(_dataDir);

        Assert.IsType<CloudSecretProtectorStub>(protector);
    }

    [Fact]
    public void WriteThenRead_RoundTripsTheProvider()
    {
        SecretStorageConfig.Write(_dataDir, SecretStorageProvider.LocalTpm);

        var provider = SecretStorageConfig.Read(_dataDir);

        Assert.Equal(SecretStorageProvider.LocalTpm, provider);
    }

    [Fact]
    public void NoConfigFile_ReadReturnsLocalFileKey()
    {
        Assert.Equal(SecretStorageProvider.LocalFileKey, SecretStorageConfig.Read(_dataDir));
    }
}
