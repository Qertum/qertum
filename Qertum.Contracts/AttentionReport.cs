using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>A condition kind the dashboard's attention view can report.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AttentionKind
{
    /// <summary>Pending requests older than the configured approval age.</summary>
    AgingApprovals,

    /// <summary>Requests the pipeline rejected with a failure reason inside the lookback window.</summary>
    FailedIssuance,

    /// <summary>Webhook deliveries that exhausted their attempts inside the lookback window.</summary>
    FailedWebhookDeliveries,

    /// <summary>The delta CRL base is lapsed, close to lapsing, or was never published.</summary>
    DeltaCrlBase,

    /// <summary>The CA certificate is close to expiry or expired.</summary>
    CaExpiry,

    /// <summary>An active or retired issuer's certificate ends within 90 days or has ended.</summary>
    IssuerExpiring,

    /// <summary>
    /// An offline issuer with an active intermediate below it has no uploaded CRL, or its uploaded CRL's
    /// nextUpdate is within 30 days or has passed.
    /// </summary>
    RootCrlExpiring,

    /// <summary>A retired issuer signed nothing that is still valid and can be archived.</summary>
    IssuerArchivable,

    /// <summary>An issuer was retired because its parent's uploaded CRL lists it as revoked.</summary>
    IssuerRevoked,

    /// <summary>A PQC exception that has not been revoked ends within 14 days.</summary>
    PqcExceptionExpiring,

    /// <summary>The last reported backup is older than its limit, or a reported recovery record cannot be read.</summary>
    RecoveryStatus,

    /// <summary>Expiry or renewal notices are open: a certificate near expiry, or a renewal stalled or failed.</summary>
    OpenNotices,

    /// <summary>Other people's requests for a second administrator's approval of a sensitive operation are waiting for a decision.</summary>
    ApprovalsWaiting
}

/// <summary>How urgent an attention item is.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum AttentionSeverity
{
    /// <summary>Needs a person soon.</summary>
    Warning,

    /// <summary>Already broken or expired.</summary>
    Critical
}

/// <summary>
/// The conditions that currently need attention, as far as the caller is permitted to see. Read-only
/// and advisory: producing it writes nothing.
/// </summary>
public sealed class AttentionReport
{
    /// <summary>UTC instant every check in this report was evaluated against.</summary>
    public DateTime GeneratedAtUtc { get; init; }

    /// <summary>Conditions that currently hold, Critical first. A kind with nothing to report is absent.</summary>
    public IReadOnlyList<AttentionItem> Items { get; init; } = [];

    /// <summary>Kinds not checked because the caller lacks the permission that guards their data.</summary>
    public IReadOnlyList<AttentionKind> WithheldKinds { get; init; } = [];

    /// <summary>Kinds whose check failed; their state is unknown, not clear.</summary>
    public IReadOnlyList<AttentionKind> UnavailableKinds { get; init; } = [];
}

/// <summary>One condition that needs attention.</summary>
public sealed class AttentionItem
{
    /// <summary>Which condition this is.</summary>
    public AttentionKind Kind { get; init; }

    /// <summary>How urgent it is.</summary>
    public AttentionSeverity Severity { get; init; }

    /// <summary>Total number of affected records; <see cref="Evidence"/> may hold fewer.</summary>
    public int Count { get; init; }

    /// <summary>One-line summary, composed from the configured thresholds.</summary>
    public string Title { get; init; } = string.Empty;

    /// <summary>Why this matters and how it clears.</summary>
    public string Explanation { get; init; } = string.Empty;

    /// <summary>Up to five records supporting the item.</summary>
    public IReadOnlyList<AttentionEvidence> Evidence { get; init; } = [];

    /// <summary>Label for the next action.</summary>
    public string ActionLabel { get; init; } = string.Empty;

    /// <summary>Web-relative path for the next action.</summary>
    public string ActionHref { get; init; } = string.Empty;
}

/// <summary>A record supporting an attention item.</summary>
public sealed class AttentionEvidence
{
    /// <summary>What the record is, e.g. a common name or webhook name.</summary>
    public string Label { get; init; } = string.Empty;

    /// <summary>Supporting detail, e.g. a failure reason.</summary>
    public string? Detail { get; init; }

    /// <summary>Web-relative path to the record, when one exists.</summary>
    public string? Href { get; init; }

    /// <summary>When the record's relevant event happened (UTC).</summary>
    public DateTime? OccurredAtUtc { get; init; }
}
