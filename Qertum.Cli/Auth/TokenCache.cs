using System.Text.Json;

namespace Qertum.Cli.Auth;

internal static class TokenCache
{
    private static readonly string CacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Qertum");

    private static readonly string CacheFile = Path.Combine(CacheDir, "cli-session.json");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    // The file holds a live access token and a refresh token: owner only, whatever the umask says.
    private const UnixFileMode OwnerFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode OwnerDirectory = OwnerFile | UnixFileMode.UserExecute;

    public static CachedSession? Load() => Load(CacheFile);

    internal static CachedSession? Load(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            using var fs = File.OpenRead(path);
            return JsonSerializer.Deserialize<CachedSession>(fs);
        }
        catch
        {
            return null;
        }
    }

    public static void Save(CachedSession session) => Save(session, CacheFile);

    internal static void Save(CachedSession session, string path)
    {
        var directory = Path.GetDirectoryName(path)!;
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(directory, OwnerDirectory);
            File.SetUnixFileMode(directory, OwnerDirectory);
            options.UnixCreateMode = OwnerFile;
            // UnixCreateMode applies only when the file is created; tighten one an older qca left readable
            // before a token is written into it.
            if (File.Exists(path)) File.SetUnixFileMode(path, OwnerFile);
        }
        else
        {
            Directory.CreateDirectory(directory);
        }
        using var fs = new FileStream(path, options);
        JsonSerializer.Serialize(fs, session, JsonOptions);
    }

    public static void Clear()
    {
        if (File.Exists(CacheFile))
            File.Delete(CacheFile);
    }

    public static string CacheFilePath { get; } = CacheFile;
}
