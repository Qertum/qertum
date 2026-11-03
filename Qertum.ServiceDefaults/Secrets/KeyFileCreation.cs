namespace Qertum.ServiceDefaults.Secrets;

/// <summary>
/// Creates a provider's key file once, however many processes start at the same moment. The CA hosts of the single
/// container all start together on an empty volume; each used to make its own key, so they could end up holding
/// different keys for one key ring. Creation is serialised by an exclusive lock file (.NET maps
/// <see cref="FileShare.None"/> to <c>flock</c> on Unix), the file is checked again under the lock, written under a
/// temporary name and renamed into place, so a process that sees the file always reads a complete one.
/// </summary>
internal static class KeyFileCreation
{
    private static readonly TimeSpan LockTimeout = TimeSpan.FromMinutes(2);

    /// <summary>Runs <paramref name="create"/> on a temporary path and renames it to <paramref name="path"/>, unless the file exists.</summary>
    public static void EnsureExists(string path, Action<string> create)
    {
        if (File.Exists(path)) return;
        using var gate = AcquireLock(path + ".lock");
        if (File.Exists(path)) return;

        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            create(temporary);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    /// <summary>
    /// Writes <paramref name="bytes"/> to a new file that only its owner can read or write from the moment it exists
    /// (Unix mode 0600 at creation, not a chmod after the write, which left a window at the umask's 0644). Windows has
    /// no mode: the data volume's inherited ACLs are the protection there.
    /// </summary>
    public static void WriteOwnerOnly(string path, byte[] bytes)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var stream = new FileStream(path, options);
        stream.Write(bytes);
    }

    private static FileStream AcquireLock(string lockPath)
    {
        var waited = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (waited.Elapsed < LockTimeout)
            {
                Thread.Sleep(50);
            }
        }
    }
}
