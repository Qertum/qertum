using System.Text.Json;

namespace Qertum.Cli.Auth;

internal static class TokenCache
{
    private static readonly string CacheDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Qertum");

    private static readonly string CacheFile = Path.Combine(CacheDir, "cli-session.json");

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static CachedSession? Load()
    {
        if (!File.Exists(CacheFile)) return null;
        try
        {
            using var fs = File.OpenRead(CacheFile);
            return JsonSerializer.Deserialize<CachedSession>(fs);
        }
        catch
        {
            return null;
        }
    }

    public static void Save(CachedSession session)
    {
        Directory.CreateDirectory(CacheDir);
        using var fs = File.Create(CacheFile);
        JsonSerializer.Serialize(fs, session, JsonOptions);
    }

    public static void Clear()
    {
        if (File.Exists(CacheFile))
            File.Delete(CacheFile);
    }

    public static string CacheFilePath { get; } = CacheFile;
}
