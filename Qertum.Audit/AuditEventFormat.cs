using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace Qertum.Audit;

/// <summary>
/// The CLEF properties an audit event carries. Both audit logs write and read these names, so the same
/// tooling reads either file; changing one breaks every reader of files already written.
/// </summary>
public static class AuditEventProperties
{
    public const string IsAuditEvent = "IsAuditEvent";
    public const string AuditEntryId = "AuditEntryId";
    public const string Action = "Action";
    public const string ResourceId = "ResourceId";
    public const string ResourceName = "ResourceName";
    public const string PerformedBy = "PerformedBy";
    public const string Detail = "Detail";
    public const string TraceId = "TraceId";
    public const string OccurredAt = "OccurredAt";
    public const string ChainWriter = "ChainWriter";
    public const string ChainSeq = "ChainSeq";
    public const string ChainPrev = "ChainPrev";
    public const string ChainHash = "ChainHash";
}

/// <summary>One audit event as read back from a CLEF line.</summary>
public sealed record AuditEventRecord(
    Guid Id,
    DateTime OccurredAtUtc,
    string Action,
    string PerformedBy,
    Guid? ResourceId,
    string? ResourceName,
    string? Detail,
    string? TraceId);

/// <summary>The chain properties of one audit line plus the fields its hash covers.</summary>
/// <param name="Writer">The chain (writer) name.</param>
/// <param name="Seq">The 1-based sequence within the chain.</param>
/// <param name="Prev">The previous entry's hash; null for the first entry of a chain.</param>
/// <param name="Hash">The entry's own hash.</param>
/// <param name="Fields">The covered fields as written.</param>
public sealed record ChainLink(string Writer, long Seq, string? Prev, string Hash, AuditChainFields Fields);

public static class AuditEventFormat
{
    /// <summary>
    /// Writes one audit event through <paramref name="log"/> with every audit property set. Returns the
    /// entry id, which is also what an indexed copy of the event keys on.
    /// </summary>
    public static Guid Write(Serilog.ILogger log, string action, string performedBy,
        Guid? resourceId = null, string? resourceName = null, string? detail = null)
    {
        var id = Guid.NewGuid();
        log.ForContext(AuditEventProperties.IsAuditEvent, true)
            .ForContext(AuditEventProperties.AuditEntryId, id)
            .ForContext(AuditEventProperties.Action, action)
            .ForContext(AuditEventProperties.ResourceId, resourceId)
            .ForContext(AuditEventProperties.ResourceName, resourceName)
            .ForContext(AuditEventProperties.PerformedBy, performedBy)
            .ForContext(AuditEventProperties.Detail, detail)
            .ForContext(AuditEventProperties.TraceId, Activity.Current?.TraceId.ToString())
            .Information("Audit {Action} by {PerformedBy}", action, performedBy);
        return id;
    }

    /// <summary>
    /// Parses one CLEF line; null for a line that is not an audit event or not valid JSON, so a reader
    /// can skip anything else sharing the file.
    /// </summary>
    public static AuditEventRecord? TryParse(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (!root.TryGetProperty(AuditEventProperties.IsAuditEvent, out var flag) || flag.ValueKind != JsonValueKind.True)
                return null;

            return new AuditEventRecord(
                Id: root.TryGetProperty(AuditEventProperties.AuditEntryId, out var id) && id.TryGetGuid(out var g) ? g : Guid.NewGuid(),
                OccurredAtUtc: root.TryGetProperty("@t", out var t) && t.GetString() is { } ts
                    ? DateTime.Parse(ts, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal)
                    : DateTime.MinValue, // no timestamp: the reader substitutes its own clock
                Action: String(root, AuditEventProperties.Action) ?? string.Empty,
                PerformedBy: String(root, AuditEventProperties.PerformedBy) ?? string.Empty,
                ResourceId: String(root, AuditEventProperties.ResourceId) is { } rid && Guid.TryParse(rid, out var r) ? r : null,
                ResourceName: String(root, AuditEventProperties.ResourceName),
                Detail: String(root, AuditEventProperties.Detail),
                TraceId: String(root, AuditEventProperties.TraceId));
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            // A malformed line is skipped, never allowed to stop a reader paging through a file.
            return null;
        }
    }

    /// <summary>Writes one audit event with its chain properties. The caller (<see cref="AuditChain"/>) computed the hash.</summary>
    public static void WriteChained(Serilog.ILogger log, Guid id, string occurredAt, string action, string performedBy,
        Guid? resourceId, string? resourceName, string? detail, string? traceId, string writer, long seq, string? prev, string hash)
    {
        log.ForContext(AuditEventProperties.IsAuditEvent, true)
            .ForContext(AuditEventProperties.AuditEntryId, id)
            .ForContext(AuditEventProperties.OccurredAt, occurredAt)
            .ForContext(AuditEventProperties.Action, action)
            .ForContext(AuditEventProperties.ResourceId, resourceId)
            .ForContext(AuditEventProperties.ResourceName, resourceName)
            .ForContext(AuditEventProperties.PerformedBy, performedBy)
            .ForContext(AuditEventProperties.Detail, detail)
            .ForContext(AuditEventProperties.TraceId, traceId)
            .ForContext(AuditEventProperties.ChainWriter, writer)
            .ForContext(AuditEventProperties.ChainSeq, seq)
            .ForContext(AuditEventProperties.ChainPrev, prev)
            .ForContext(AuditEventProperties.ChainHash, hash)
            .Information("Audit {Action} by {PerformedBy}", action, performedBy);
    }

    /// <summary>
    /// Parses the chain properties of one CLEF line; null for a line that is not an audit event, has no chain
    /// (written before the chain existed) or is not valid JSON.
    /// </summary>
    public static ChainLink? TryParseChain(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (!root.TryGetProperty(AuditEventProperties.IsAuditEvent, out var flag) || flag.ValueKind != JsonValueKind.True)
                return null;
            if (String(root, AuditEventProperties.ChainWriter) is not { } writer || String(root, AuditEventProperties.ChainHash) is not { } hash)
                return null;
            if (!root.TryGetProperty(AuditEventProperties.ChainSeq, out var seqElement) || !seqElement.TryGetInt64(out var seq))
                return null;

            var fields = new AuditChainFields(
                String(root, AuditEventProperties.AuditEntryId) ?? string.Empty,
                String(root, AuditEventProperties.OccurredAt) ?? string.Empty,
                String(root, AuditEventProperties.Action) ?? string.Empty,
                String(root, AuditEventProperties.PerformedBy) ?? string.Empty,
                String(root, AuditEventProperties.ResourceId) ?? string.Empty,
                String(root, AuditEventProperties.ResourceName) ?? string.Empty,
                String(root, AuditEventProperties.Detail) ?? string.Empty,
                String(root, AuditEventProperties.TraceId) ?? string.Empty);
            return new ChainLink(writer, seq, String(root, AuditEventProperties.ChainPrev), hash, fields);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? String(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
