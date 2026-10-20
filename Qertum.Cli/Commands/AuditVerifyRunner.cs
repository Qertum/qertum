using System.Text.Json;
using Qertum.Audit;

namespace Qertum.Cli.Commands;

/// <summary>The work of <c>qca audit verify</c>, writing to the given writers so it can be tested without capturing the console.</summary>
internal static class AuditVerifyRunner
{
    /// <summary>
    /// Verifies the chains in <paramref name="paths"/> (files, or directories of <c>*.clef</c>). Returns 0 when every chain
    /// is intact and any anchor matched, 1 when a chain is broken or the anchor does not match, 2 when nothing could be
    /// read or the anchor file is not valid.
    /// </summary>
    public static int Run(IReadOnlyList<string> paths, string? anchorPath, TextWriter output, TextWriter error)
    {
        var files = new List<string>();
        foreach (var path in paths)
        {
            if (Directory.Exists(path))
                files.AddRange(Directory.GetFiles(path, "*.clef"));
            else if (File.Exists(path))
                files.Add(path);
            else
            {
                error.WriteLine($"Not found: {path}");
                return 2;
            }
        }

        if (files.Count == 0)
        {
            error.WriteLine("No .clef files found.");
            return 2;
        }

        IReadOnlyList<AuditAnchorHead>? anchor = null;
        if (anchorPath is not null)
        {
            try
            {
                anchor = ReadAnchor(File.ReadAllText(anchorPath));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException or FormatException)
            {
                error.WriteLine($"The anchor file could not be read: {ex.GetType().Name}.");
                return 2;
            }
        }

        AuditChainReport report;
        try
        {
            report = AuditChainVerifier.Verify(files, anchor);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            error.WriteLine($"A log file could not be read: {ex.GetType().Name}.");
            return 2;
        }

        if (report.Chains.Count == 0)
            output.WriteLine("No chained audit entries found (entries written before the chain existed are not checked).");
        foreach (var chain in report.Chains)
        {
            output.WriteLine(chain.Problem is { } p
                ? $"{chain.Writer,-28}  BROKEN  {p.Kind}{(p.Line > 0 ? $" at {Path.GetFileName(p.File)}:{p.Line}" : string.Empty)}{(p.Seq is { } s ? $" (seq {s})" : string.Empty)}"
                : $"{chain.Writer,-28}  ok      seq {chain.FirstSeq}..{chain.LastSeq} ({chain.Entries} entries)");
        }

        return report.Ok ? 0 : 1;
    }

    /// <summary>Accepts the checkpoint object (<c>{ "chains": [...] }</c>, either casing) or the bare heads array the webhook carries.</summary>
    private static List<AuditAnchorHead> ReadAnchor(string json)
    {
        using var doc = JsonDocument.Parse(json);
        JsonElement array;
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
            array = doc.RootElement;
        else if (!(doc.RootElement.ValueKind == JsonValueKind.Object
                   && (doc.RootElement.TryGetProperty("chains", out array) || doc.RootElement.TryGetProperty("Chains", out array))))
            throw new InvalidOperationException("no chains");

        return array.EnumerateArray().Select(e => new AuditAnchorHead(
            Pick(e, "writer", "Writer").GetString() ?? throw new InvalidOperationException("writer"),
            Pick(e, "seq", "Seq").GetInt64(),
            Pick(e, "hash", "Hash").GetString() ?? throw new InvalidOperationException("hash"))).ToList();
    }

    private static JsonElement Pick(JsonElement element, string camel, string pascal) =>
        element.TryGetProperty(camel, out var v) || element.TryGetProperty(pascal, out v) ? v : throw new InvalidOperationException(camel);
}
