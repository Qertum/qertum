using System.Text.Json;
using Microsoft.Extensions.Options;

namespace Qertum.Services;

/// <summary>
/// Reads audit log entries from CLEF (Compact Log Event Format) rolling files written by
/// <see cref="SerilogAuditLogService"/>. Entries are returned newest-first without loading
/// the entire log into memory — only as many lines as required for the requested page are read.
/// </summary>
public sealed class AuditLogFileReader(IOptions<AuditLogOptions> options, TimeProvider? timeProvider = null)
{
    // Time is read through TimeProvider so expiry and scheduling can be tested with a fake clock;
    // optional so code that constructs this directly keeps compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    private readonly AuditLogOptions _options = options.Value;

    /// <summary>Returns a page of audit log entries, newest first.</summary>
    public async Task<IReadOnlyList<AuditLogEntry>> ReadAsync(
        int page = 1,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        pageSize = Math.Clamp(pageSize, 1, 500);
        page = Math.Max(1, page);

        var skip = (page - 1) * pageSize;
        var result = new List<AuditLogEntry>(pageSize);
        var skipped = 0;

        foreach (var filePath in GetAuditFilesNewestFirst())
        {
            cancellationToken.ThrowIfCancellationRequested();

            string[] lines;
            try
            {
                // FileShare.ReadWrite lets us read while Serilog (or a second service instance)
                // still holds the file open for appending with shared: true.
                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite, bufferSize: 4096, useAsync: true);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(cancellationToken);
                lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            }
            catch (IOException)
            {
                continue; // skip files that are transiently locked or deleted mid-run
            }

            // CLEF files are written oldest-first; iterate in reverse for newest-first order.
            for (var i = lines.Length - 1; i >= 0; i--)
            {
                var entry = ParseLine(lines[i]);
                if (entry is null) continue;

                if (skipped < skip) { skipped++; continue; }

                result.Add(entry);
                if (result.Count >= pageSize) return result;
            }
        }

        return result;
    }

    private string[] GetAuditFilesNewestFirst() => Qertum.Audit.AuditLogFiles.NewestFirst(_options.File.Path);

    private AuditLogEntry? ParseLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;

        // Normal app log lines can share the file; TryParse returns null for anything not an audit event.
        if (Qertum.Audit.AuditEventFormat.TryParse(line) is not { } e) return null;

        return new AuditLogEntry
        {
            Id = e.Id,
            Action = e.Action,
            ResourceId = e.ResourceId,
            ResourceName = e.ResourceName,
            PerformedBy = e.PerformedBy,
            OccurredAtUtc = e.OccurredAtUtc == DateTime.MinValue ? _clock.GetUtcNow().UtcDateTime : e.OccurredAtUtc,
            Detail = e.Detail,
            TraceId = e.TraceId
        };
    }
}
