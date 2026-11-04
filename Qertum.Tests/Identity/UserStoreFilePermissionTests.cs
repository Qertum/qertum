using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

public sealed class UserStoreFilePermissionTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("qertum-users-mode-").FullName;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose() => Directory.Delete(_directory, recursive: true);

    private JsonUserStore OpenStore() => new(NullLogger<JsonUserStore>.Instance, _directory);

    [Fact]
    public void SeededPasswordHashes_AreReadableByOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }

        var store = OpenStore();

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(store.FilePath));
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp*"));
    }

    [Fact]
    public async Task OpeningAnExistingStore_RepairsPermissionsWithoutChangingUsers()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var store = OpenStore();
        var original = await File.ReadAllBytesAsync(store.FilePath, Ct);
        File.SetUnixFileMode(store.FilePath, OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        var reopened = OpenStore();

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(reopened.FilePath));
        Assert.Equal(original, await File.ReadAllBytesAsync(reopened.FilePath, Ct));
    }

    [Fact]
    public async Task UpdatingUsers_ReplacesTheFileWithOwnerOnlyPermissions()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var store = OpenStore();
        var admin = (await store.FindByUsernameAsync("admin", Ct))!;
        File.SetUnixFileMode(store.FilePath, OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        await store.UpdateProfileAsync(admin.Id, "Updated administrator", admin.Email, Ct);

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(store.FilePath));
        Assert.Equal("Updated administrator", (await store.FindByIdAsync(admin.Id, Ct))!.DisplayName);
        Assert.Empty(Directory.GetFiles(_directory, "*.tmp*"));
    }

    [Fact]
    public async Task UpdatingUsers_DoesNotFollowTheOldPredictableTemporarySymlink()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix symbolic links only."); return; }
        var store = OpenStore();
        var admin = (await store.FindByUsernameAsync("admin", Ct))!;
        var target = Path.Combine(_directory, "unrelated.txt");
        await File.WriteAllTextAsync(target, "keep this file", Ct);
        File.CreateSymbolicLink(store.FilePath + ".tmp", target);

        await store.UpdateProfileAsync(admin.Id, "Updated administrator", admin.Email, Ct);

        Assert.Equal("keep this file", await File.ReadAllTextAsync(target, Ct));
        Assert.Equal("Updated administrator", (await store.FindByIdAsync(admin.Id, Ct))!.DisplayName);
    }
}
