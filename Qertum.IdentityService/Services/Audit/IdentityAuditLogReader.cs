using System.Globalization;
using System.Text.Json;

namespace Qertum.IdentityService.Services.Audit;

/// <summary>
/// Reads <see cref="IdentityAuditLog"/> files newest first. Mirrors the CA's AuditLogFileReader
/// rather than referencing it, so the identity provider stays deployable on its own.
/// </summary>
/// <summary>Filters for the audit view. An unset member is ignored; all set members must match.</summary>
/// <param name="Action">Exact action name, e.g. <c>RoleRenamed</c>.</param>
/// <param name="Actor">Case-insensitive substring of the acting identity.</param>
/// <param name="From">Inclusive lower bound, UTC date.</param>
/// <param name="To">Inclusive upper bound, UTC date.</param>
/// <param name="Text">Case-insensitive substring of the rendered message.</param>
public sealed record IdentityAuditQuery(
    string? Action = null, string? Actor = null, DateOnly? From = null, DateOnly? To = null, string? Text = null)
{
    /// <summary>True when no filter is set.</summary>
    public bool IsEmpty => string.IsNullOrWhiteSpace(Action) && string.IsNullOrWhiteSpace(Actor)
        && From is null && To is null && string.IsNullOrWhiteSpace(Text);

    internal bool Matches(IdentityAuditEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(Action) && !string.Equals(entry.Action, Action, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!string.IsNullOrWhiteSpace(Actor) && !entry.PerformedBy.Contains(Actor, StringComparison.OrdinalIgnoreCase))
            return false;
        if (From is { } from && DateOnly.FromDateTime(entry.OccurredAtUtc) < from)
            return false;
        if (To is { } to && DateOnly.FromDateTime(entry.OccurredAtUtc) > to)
            return false;
        if (!string.IsNullOrWhiteSpace(Text) && !EntryText(entry).Contains(Text, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private static string EntryText(IdentityAuditEntry entry) =>
        string.Join(' ', new[] { entry.Action, entry.PerformedBy, entry.ResourceName, entry.Detail }
            .Where(v => !string.IsNullOrEmpty(v)));
}

/// <summary>One page of audit entries.</summary>
/// <param name="Entries">The page's entries, newest first.</param>
/// <param name="HasOlder">Whether at least one more entry matched beyond this page.</param>
/// <param name="Truncated">Whether the scan stopped at <see cref="IdentityAuditLogReader.MaxEntriesScanned"/>.</param>
public sealed record IdentityAuditPage(IReadOnlyList<IdentityAuditEntry> Entries, bool HasOlder, bool Truncated);

public sealed class IdentityAuditLogReader(string? path, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Upper bound on entries examined for one page, so a long retention cannot hang the page.</summary>
    public const int MaxEntriesScanned = 20_000;

    /// <summary>Reads one page of entries matching <paramref name="query"/>, newest first.</summary>
    public async Task<IdentityAuditPage> ReadAsync(
        IdentityAuditQuery query, int skip, int take, CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 500);
        skip = Math.Max(0, skip);

        var result = new List<IdentityAuditEntry>(take);
        var skipped = 0;
        var scanned = 0;
        var truncated = false;
        var hasOlder = false;

        foreach (var file in FilesNewestFirst())
        {
            cancellationToken.ThrowIfCancellationRequested();

            string content;
            try
            {
                // ReadWrite sharing: the writer keeps the file open with shared: true.
                await using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, useAsync: true);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(cancellationToken);
            }
            catch (IOException)
            {
                continue;
            }

            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            for (var i = lines.Length - 1; i >= 0; i--)
            {
                if (++scanned > MaxEntriesScanned)
                {
                    truncated = true;
                    break;
                }

                var entry = Parse(lines[i]);
                if (entry is null || !query.Matches(entry))
                {
                    continue;
                }

                if (skipped < skip)
                {
                    skipped++;
                    continue;
                }

                if (result.Count == take)
                {
                    hasOlder = true;
                    break;
                }

                result.Add(entry);
            }

            if (truncated || hasOlder)
            {
                break;
            }
        }

        return new IdentityAuditPage(result, hasOlder, truncated);
    }

    public async Task<IReadOnlyList<IdentityAuditEntry>> ReadAsync(int skip, int take, CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, 500);
        skip = Math.Max(0, skip);

        var result = new List<IdentityAuditEntry>(take);
        var skipped = 0;

        foreach (var file in FilesNewestFirst())
        {
            cancellationToken.ThrowIfCancellationRequested();

            string content;
            try
            {
                // ReadWrite sharing: the writer keeps the file open with shared: true.
                await using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, useAsync: true);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(cancellationToken);
            }
            catch (IOException)
            {
                continue;
            }

            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            for (var i = lines.Length - 1; i >= 0; i--)
            {
                var entry = Parse(lines[i]);
                if (entry is null)
                {
                    continue;
                }

                if (skipped < skip)
                {
                    skipped++;
                    continue;
                }

                result.Add(entry);
                if (result.Count >= take)
                {
                    return result;
                }
            }
        }

        return result;
    }

    private string[] FilesNewestFirst()
    {
        if (string.IsNullOrEmpty(path))
        {
            return [];
        }

        var dir = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
        {
            return [];
        }

        var name = Path.GetFileName(path);
        var dot = name.LastIndexOf('.');
        var stem = dot > 0 ? name[..dot] : name;
        var ext = dot > 0 ? name[dot..] : string.Empty;

        string[] files;
        try
        {
            files = Directory.GetFiles(dir, $"{stem}*{ext}");
        }
        catch (IOException)
        {
            return [];
        }

        // Serilog's date-stamped names sort lexicographically in date order.
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);
        Array.Reverse(files);
        return files;
    }

    private IdentityAuditEntry? Parse(string line) =>
        Qertum.Audit.AuditEventFormat.TryParse(line) is { } e
            ? new IdentityAuditEntry(
                Id: e.Id,
                OccurredAtUtc: e.OccurredAtUtc == DateTime.MinValue ? _clock.GetUtcNow().UtcDateTime : e.OccurredAtUtc,
                Action: e.Action,
                PerformedBy: e.PerformedBy,
                ResourceId: e.ResourceId,
                ResourceName: e.ResourceName,
                Detail: e.Detail,
                TraceId: e.TraceId)
            : null;
}
