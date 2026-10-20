namespace Qertum.Audit;

/// <summary>Finds the rolling CLEF files a configured audit path produces.</summary>
public static class AuditLogFiles
{
    /// <summary>
    /// The files Serilog's rolling sink wrote for <paramref name="configuredPath"/> (for example
    /// <c>audit-.clef</c> gives <c>audit-20260524.clef</c>), newest first. Empty when the path is empty or the
    /// directory does not exist.
    /// </summary>
    /// <param name="configuredPath">The configured file path with the date stripped, as given to the sink.</param>
    public static string[] NewestFirst(string? configuredPath)
    {
        if (string.IsNullOrEmpty(configuredPath))
            return [];

        var dir = Path.GetDirectoryName(configuredPath);
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            return [];

        var filename = Path.GetFileName(configuredPath);
        var dotIdx = filename.LastIndexOf('.');
        var stem = dotIdx > 0 ? filename[..dotIdx] : filename;
        var ext = dotIdx > 0 ? filename[dotIdx..] : string.Empty;

        string[] files;
        try
        {
            files = Directory.GetFiles(dir, $"{stem}*{ext}");
        }
        catch (IOException)
        {
            return [];
        }

        // Lexicographic descending equals date descending for Serilog's date-appended names.
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        Array.Reverse(files);
        return files;
    }
}
