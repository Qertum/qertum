using Qertum.Cli;

namespace Qertum.Tests.Cli;

/// <summary>
/// qca writes private keys and PKCS#12 bundles to disk. The cert download-key and export commands used
/// File.WriteAllBytesAsync, so the files got the umask's mode (often 0644, readable by every local user); the issuer
/// export already wrote owner-only. Every key-bearing file now goes through <see cref="SecretFile"/>.
/// </summary>
public sealed class SecretFileTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("qca-secret-").FullName;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    [Fact]
    public async Task ANewFile_IsReadableByItsOwnerOnly()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        var path = Path.Combine(_dir, "leaf.key");

        await SecretFile.WriteAsync(path, "key"u8.ToArray(), overwrite: true, Ct);

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(path));
        Assert.Equal("key"u8.ToArray(), await File.ReadAllBytesAsync(path, Ct));
    }

    [Fact]
    public async Task OverwritingAnOpenFile_NarrowsItToTheOwnerFirst()
    {
        if (OperatingSystem.IsWindows()) { Assert.Skip("Unix file modes only."); return; }
        // A key downloaded by an older qca sits there world-readable; a new download must not keep that mode.
        var path = Path.Combine(_dir, "leaf.key");
        await File.WriteAllBytesAsync(path, "old-key-material-longer"u8.ToArray(), Ct);
        File.SetUnixFileMode(path, OwnerOnly | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        await SecretFile.WriteAsync(path, "new"u8.ToArray(), overwrite: true, Ct);

        Assert.Equal(OwnerOnly, File.GetUnixFileMode(path));
        Assert.Equal("new"u8.ToArray(), await File.ReadAllBytesAsync(path, Ct));
    }

    [Fact]
    public async Task WithoutOverwrite_AnExistingFileIsRefusedAndKept()
    {
        var path = Path.Combine(_dir, "ca.key");
        await File.WriteAllBytesAsync(path, "keep"u8.ToArray(), Ct);

        await Assert.ThrowsAsync<IOException>(() => SecretFile.WriteAsync(path, "new"u8.ToArray(), overwrite: false, Ct));
        Assert.Equal("keep"u8.ToArray(), await File.ReadAllBytesAsync(path, Ct));
    }
}
