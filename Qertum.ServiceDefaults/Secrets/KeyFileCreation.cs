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
