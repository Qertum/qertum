using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>How a reported recovery record compares with its limit.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RecoveryItemState
{
    /// <summary>A valid record, no older than its limit.</summary>
    Fresh,

    /// <summary>A valid record, older than its limit.</summary>
    Stale,

    /// <summary>No record exists. Not a failure: a deployment may back up another way.</summary>
    NotReported,

    /// <summary>A record exists but cannot be trusted (damaged, too large, unknown version, or dated in the future).</summary>
    Unreadable,

    /// <summary>A valid record that is shown but never compared with a limit: a restore that was performed, not verified.</summary>
    NotJudged,

    /// <summary>The last restore test failed. Never compared with a limit: it stays until a passing run replaces it.</summary>
    Failed
}

/// <summary>What a host script reported about one recovery step, and how it compares with its limit.</summary>
public sealed class RecoveryItem
{
    /// <summary>How the record compares with its limit.</summary>
    public RecoveryItemState State { get; init; } = RecoveryItemState.NotReported;

    /// <summary>When the script says the step finished (UTC). Null unless a valid record exists.</summary>
    public DateTime? CompletedAtUtc { get; init; }

    /// <summary>Name of the archive the script reported.</summary>
    public string? ArchiveName { get; init; }

    /// <summary>Size of the archive in bytes, when the script reported it.</summary>
    public long? SizeBytes { get; init; }

    /// <summary>For a restore record, <c>performed</c>, <c>verified</c>, <c>usable</c> or <c>failed</c>; null for a backup.</summary>
    public string? Kind { get; init; }

    /// <summary>For a failed restore test, the step that failed: <c>manifest</c> or <c>usability</c>; otherwise null.</summary>
    public string? Step { get; init; }

    /// <summary>For a failed restore test, the name of the check that failed (for example <c>key-ring</c>); otherwise null.</summary>
    public string? FailedCheck { get; init; }

    /// <summary>Which script wrote the record, as it reported itself. Not authenticated.</summary>
    public string? ReportedBy { get; init; }

    /// <summary>The limit, in hours, the age was compared with; null when the record is not judged.</summary>
    public int? ThresholdHours { get; init; }

    /// <summary>Fixed text saying why a record is <see cref="RecoveryItemState.Unreadable"/>; never file content.</summary>
    public string? Problem { get; init; }
}

/// <summary>
/// The last backup and last restore as reported by the scripts on the host. Reported, not verified:
/// Qertum has not checked the archive or that a restore works.
/// </summary>
public sealed class RecoveryStatus
{
    /// <summary>UTC instant the status was evaluated; the age of a record is this minus its completion time.</summary>
    public DateTime GeneratedAtUtc { get; init; }

    /// <summary>The last backup.</summary>
    public RecoveryItem Backup { get; init; } = new();

    /// <summary>The last restore.</summary>
    public RecoveryItem Restore { get; init; } = new();
}
