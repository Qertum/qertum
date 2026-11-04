using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

public sealed class ClientStoreFilePermissionTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("qertum-clients-mode-").FullName;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private JsonClientStore OpenStore(bool seedTests = false) => new(NullLogger<JsonClientStore>.Instance,
        new Lifetime(), new IdentityServiceOptions { SeedTestClients = seedTests }, _directory);

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }

    [Fact]
    public void ClientAndOneTimeSecretFiles_AreOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var store = OpenStore();

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(store.FilePath));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(Path.Combine(_directory, "api-client-secret.txt")));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp*"));
    }

    [Fact]
    public void OpeningExistingClients_RepairsPermissionsWithoutReplacingSecrets()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var store = OpenStore();
        var original = File.ReadAllBytes(store.FilePath);
        var secretPath = Path.Combine(_directory, "api-client-secret.txt");
        File.SetUnixFileMode(store.FilePath, OwnerOnly | UnixFileMode.OtherRead);
        File.SetUnixFileMode(secretPath, OwnerOnly | UnixFileMode.OtherRead);

        OpenStore();

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(store.FilePath));
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(secretPath));
        Assert.Equal(original, File.ReadAllBytes(store.FilePath));
    }

    [Fact]
    public void RemovingTestClients_ReplacesTheStoreWithOwnerOnlyPermissions()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var store = OpenStore(seedTests: true);
        File.SetUnixFileMode(store.FilePath, OwnerOnly | UnixFileMode.OtherRead);

        var reopened = OpenStore();

        Assert.DoesNotContain(reopened.GetAll(), client => client.ClientId == "qertum-test-m2m");
        Assert.Equal(OwnerOnly, File.GetUnixFileMode(store.FilePath));
    }
}
