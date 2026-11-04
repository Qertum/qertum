namespace Qertum.IdentityService.Stores;

/// <summary>Writes identity secrets privately and replaces complete files atomically.</summary>
internal static class PrivateStoreFile
{
    public static void RestrictAccess(string path)
    {
        if (!OperatingSystem.IsWindows() && File.Exists(path))
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    public static void Write(string path, Action<Stream> write)
    {
        // Never reuse a predictable path or write secrets before restricting access.
        var temporary = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        var stream = new FileStream(temporary, options);
        try
        {
            using (stream) write(stream);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }
}
