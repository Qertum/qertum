using System.Diagnostics;
using System.Globalization;
using System.Reflection;

namespace Qertum.Audit;

/// <summary>
/// The writer side of the audit hash chain: one per process, one chain per writer name. Hashing and the log call
/// happen under one lock, so one writer's lines appear in the file in sequence order. The head is recovered from
/// the newest files at construction, so a restart continues the chain.
/// </summary>
public sealed class AuditChain
{
    private readonly object _gate = new();
    private readonly TimeProvider _clock;
    private long _seq;
    private string? _hash;

    /// <summary>The chain name written to every line.</summary>
    public string Writer { get; }

    /// <summary>
    /// Creates the chain and recovers its head from <paramref name="filesNewestFirst"/>: the newest file holding a line of this
    /// writer, however many newer files belong to other writers.
    /// </summary>
    /// <param name="writer">The chain name; stable across restarts.</param>
    /// <param name="filesNewestFirst">Existing audit files, newest first (see <see cref="AuditLogFiles.NewestFirst"/>).</param>
    /// <param name="clock">The clock for <c>OccurredAt</c>; system time when null.</param>
    public AuditChain(string writer, IEnumerable<string> filesNewestFirst, TimeProvider? clock = null)
    {
        Writer = writer;
        _clock = clock ?? TimeProvider.System;
        (_seq, _hash) = RecoverHead(writer, filesNewestFirst);
    }

    /// <summary>The entry assembly name, lower-cased (for example <c>qertum.apiservice</c>); <c>unknown</c> when there is none.</summary>
    public static string DefaultWriter() => (Assembly.GetEntryAssembly()?.GetName().Name ?? "unknown").ToLowerInvariant();

    /// <summary>Writes one chained audit event through <paramref name="log"/> and returns its entry id.</summary>
    public Guid Write(Serilog.ILogger log, string action, string performedBy,
        Guid? resourceId = null, string? resourceName = null, string? detail = null)
    {
        lock (_gate)
        {
            var id = Guid.NewGuid();
            var seq = _seq + 1;
            var occurredAt = _clock.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
            var traceId = Activity.Current?.TraceId.ToString();
            var fields = new AuditChainFields(
                id.ToString(), occurredAt, action, performedBy,
                resourceId?.ToString() ?? string.Empty, resourceName ?? string.Empty, detail ?? string.Empty, traceId ?? string.Empty);
            var hash = AuditChainHasher.Compute(_hash, Writer, seq, fields);

            AuditEventFormat.WriteChained(log, id, occurredAt, action, performedBy, resourceId, resourceName, detail, traceId, Writer, seq, _hash, hash);

            _seq = seq;
            _hash = hash;
            return id;
        }
    }

    private static (long Seq, string? Hash) RecoverHead(string writer, IEnumerable<string> files)
    {
        foreach (var file in files)
        {
            string[] lines;
            try
            {
                using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var reader = new StreamReader(stream);
                lines = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
            }
            catch (IOException)
            {
                continue;
            }

            for (var i = lines.Length - 1; i >= 0; i--)
                if (AuditEventFormat.TryParseChain(lines[i]) is { } link && string.Equals(link.Writer, writer, StringComparison.Ordinal))
                    return (link.Seq, link.Hash);
        }

        return (0, null);
    }
}
