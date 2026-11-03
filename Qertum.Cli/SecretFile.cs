namespace Qertum.Cli;

/// <summary>
/// Writes key material (private keys, PKCS#12 bundles) so only the file's owner can read it. A plain
/// <c>File.WriteAllBytesAsync</c> gets the umask's mode, often 0644, which every local user can read.
/// </summary>
internal static class SecretFile
{
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>
    /// Writes <paramref name="bytes"/> to <paramref name="path"/> with mode 0600 (Unix; Windows has no mode and relies on
    /// the folder's ACLs). With <paramref name="overwrite"/> an existing file is narrowed to 0600 before it is rewritten,
    /// so a file an older qca left readable does not keep that mode; without it an existing file is refused
    /// (<see cref="IOException"/>) and left as it is.
    /// </summary>
    public static async Task WriteAsync(string path, byte[] bytes, bool overwrite, CancellationToken ct)
    {
        if (overwrite && !OperatingSystem.IsWindows() && File.Exists(path))
            File.SetUnixFileMode(path, OwnerOnly);

        var options = new FileStreamOptions
        {
            Mode = overwrite ? FileMode.Create : FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None
        };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = OwnerOnly;
        await using var stream = new FileStream(path, options);
        await stream.WriteAsync(bytes, ct);
    }
}
