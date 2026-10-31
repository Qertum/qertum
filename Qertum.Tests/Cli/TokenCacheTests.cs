using Qertum.Cli.Auth;

namespace Qertum.Tests.Cli;

/// <summary>
/// The session file holds a live access token and a refresh token. It used to be created with the
/// umask's mode, which on most Unix systems lets every local user read it.
/// </summary>
public sealed class TokenCacheTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "qca-cache-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static CachedSession Session() => new()
    {
        AccessToken = "at", RefreshToken = "rt", Username = "u",
        ExpiresAt = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero)
    };

    [Fact]
    public void TheSessionFileAndItsFolderAreReadableByTheOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) return; // per-user profile ACLs; no Unix mode to check

        var file = Path.Combine(_dir, "cli-session.json");
        TokenCache.Save(Session(), file);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(_dir));
    }

    [Fact]
    public void AnExistingReadableSessionFileIsTightenedOnSave()
    {
        if (OperatingSystem.IsWindows()) return;

        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "cli-session.json");
        File.WriteAllText(file, "{}");
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        TokenCache.Save(Session(), file);

        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
        Assert.Equal("at", TokenCache.Load(file)!.AccessToken);
    }
}
