using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>What a bulk operation does to every certificate in it.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum BulkOperationKind
{
    /// <summary>Queue each certificate for revocation.</summary>
    Revoke = 0,
    /// <summary>File a renewal request for each certificate; renewals start <c>Pending</c>.</summary>
    Renew = 1
}

/// <summary>Lifecycle of a bulk operation, stored as its name.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum BulkOperationStatus
{
    /// <summary>Items are frozen; nothing has run. Waiting for execute, cancel or expiry.</summary>
    Previewed = 0,
    /// <summary>Execute was accepted; the background job is working through the items.</summary>
    Running = 1,
    /// <summary>Every item is done or skipped.</summary>
    Completed = 2,
    /// <summary>The run finished and at least one item failed.</summary>
    CompletedWithErrors = 3,
    /// <summary>Cancelled before execute.</summary>
    Cancelled = 4,
    /// <summary>The preview outlived <c>BulkOperations:PreviewTtlMinutes</c> without being executed.</summary>
    Expired = 5
}

/// <summary>Result of one item, stored as its name.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum BulkItemOutcome
{
    /// <summary>Not processed yet.</summary>
    Pending = 0,
    /// <summary>The single-item action succeeded.</summary>
    Done = 1,
    /// <summary>The certificate was no longer eligible when its turn came; nothing was changed.</summary>
    Skipped = 2,
    /// <summary>The single-item action refused or failed; <see cref="BulkOperationItem.Detail"/> says why.</summary>
    Failed = 3
}

/// <summary>
/// One persisted bulk revoke or renew: the filter the operator used, the frozen list of requests it
/// matched (<see cref="BulkOperationItem"/>) and the progress of the run.
/// </summary>
public sealed class BulkOperation
{
    /// <summary>Operation identifier.</summary>
    public BulkOperationId Id { get; set; } = new(Guid.NewGuid());
    /// <summary>Revoke or renew.</summary>
    public BulkOperationKind Kind { get; set; }
    /// <summary>Current state.</summary>
    public BulkOperationStatus Status { get; set; } = BulkOperationStatus.Previewed;
    /// <summary>The <see cref="BulkOperationFilter"/> as JSON, kept for the audit trail.</summary>
    public string FilterJson { get; set; } = "{}";
    /// <summary>Revocation reason; required for <see cref="BulkOperationKind.Revoke"/>, null for renew.</summary>
    public string? Reason { get; set; }
    /// <summary>Display name of the identity that previewed it.</summary>
    public string CreatedBy { get; set; } = string.Empty;
    /// <summary>Stable subject of the identity that previewed it; null only for legacy callers without one.</summary>
    public string? CreatedBySubject { get; set; }
    /// <summary>When the preview was made (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }
    /// <summary>Display name of the identity that executed it.</summary>
    public string? ExecutedBy { get; set; }
    /// <summary>When execute was accepted (UTC).</summary>
    public DateTime? ExecutedAtUtc { get; set; }
    /// <summary>When the job began (UTC).</summary>
    public DateTime? StartedAtUtc { get; set; }
    /// <summary>When the run reached a final status (UTC).</summary>
    public DateTime? FinishedAtUtc { get; set; }
    /// <summary>The executor's <see cref="BulkCallerSnapshot"/> as JSON; used to rebuild the policy caller in the job.</summary>
    public string? CallerSnapshotJson { get; set; }
    /// <summary>Number of items frozen at preview.</summary>
    public int ItemCount { get; set; }
    /// <summary>Items that succeeded.</summary>
    public int DoneCount { get; set; }
    /// <summary>Items that were no longer eligible when processed.</summary>
    public int SkippedCount { get; set; }
    /// <summary>Items that failed.</summary>
    public int FailedCount { get; set; }
    /// <summary>Counts of matched requests left out at preview, by reason, as JSON.</summary>
    public string? ExcludedJson { get; set; }
}

/// <summary>One certificate request frozen into a bulk operation. Key: (<see cref="OperationId"/>, <see cref="RequestId"/>).</summary>
public sealed class BulkOperationItem
{
    /// <summary>The owning operation.</summary>
    public BulkOperationId OperationId { get; set; }
    /// <summary>The certificate request acted on.</summary>
    public CertificateRequestId RequestId { get; set; }
    /// <summary>Result of this item.</summary>
    public BulkItemOutcome Outcome { get; set; } = BulkItemOutcome.Pending;
    /// <summary>Why the item was skipped or failed, or a short note when done.</summary>
    public string? Detail { get; set; }
    /// <summary>For renew: the new request that was filed.</summary>
    public CertificateRequestId? ResultRequestId { get; set; }
}

/// <summary>
/// Which certificates a bulk operation selects. Either at least one criterion, or <see cref="All"/>
/// alone; an empty filter, or <see cref="All"/> with a criterion, is refused.
/// </summary>
public sealed class BulkOperationFilter
{
    /// <summary>Only certificates signed under this issuer.</summary>
    public IssuerId? IssuerId { get; set; }
    /// <summary>Only certificates of this template (<c>CertificateRequest.Type</c>).</summary>
    public string? TemplateKey { get; set; }
    /// <summary>Only certificates owned by this subject (<c>RequestedBySubject</c>).</summary>
    public string? OwnerSubject { get; set; }
    /// <summary><c>ValidTo</c> at or before this instant (UTC); includes already-expired issued certificates.</summary>
    public DateTime? ValidToBefore { get; set; }
    /// <summary><c>ValidTo</c> at or after this instant (UTC).</summary>
    public DateTime? ValidToAfter { get; set; }
    /// <summary>Sugar for <see cref="ValidToBefore"/> = now + this many days. Ignored when <see cref="ValidToBefore"/> is set.</summary>
    public int? ExpiresWithinDays { get; set; }
    /// <summary>Only common names containing this text (matched literally, case-insensitively for ASCII).</summary>
    public string? CommonNameContains { get; set; }
    /// <summary>Select every eligible certificate. Cannot be combined with any other field.</summary>
    public bool All { get; set; }

    /// <summary>True when no criterion is set (ignoring <see cref="All"/>).</summary>
    [JsonIgnore]
    public bool HasCriterion =>
        IssuerId is not null || !string.IsNullOrWhiteSpace(TemplateKey) || !string.IsNullOrWhiteSpace(OwnerSubject)
        || ValidToBefore is not null || ValidToAfter is not null || ExpiresWithinDays is not null
        || !string.IsNullOrWhiteSpace(CommonNameContains);
}

/// <summary>The executor's rights at execute time, stored on the operation so the job can evaluate policy as them.</summary>
/// <param name="Subject">Stable subject, if the identity has one.</param>
/// <param name="Name">Display name.</param>
/// <param name="IsAdmin">Holds the admin role.</param>
/// <param name="HoldsCaPermission">Holds <c>certificates.ca</c>.</param>
public sealed record BulkCallerSnapshot(string? Subject, string Name, bool IsAdmin, bool HoldsCaPermission);

/// <summary>Body of <c>POST /v1/bulk-operations/preview</c>.</summary>
/// <param name="Kind">Revoke or renew.</param>
/// <param name="Filter">What to select.</param>
/// <param name="Reason">Revocation reason; required for revoke.</param>
public sealed record PreviewBulkOperationRequest(BulkOperationKind Kind, BulkOperationFilter Filter, string? Reason = null);

/// <summary>Body of <c>POST /v1/bulk-operations/{id}/execute</c>.</summary>
/// <param name="ConfirmCount">Must equal the operation's item count.</param>
public sealed record ExecuteBulkOperationRequest(int ConfirmCount);

/// <summary>An operation as clients see it. Never carries certificate content.</summary>
public sealed class BulkOperationView
{
    /// <summary>Operation identifier.</summary>
    public BulkOperationId Id { get; init; }
    /// <summary>Revoke or renew.</summary>
    public BulkOperationKind Kind { get; init; }
    /// <summary>Current state.</summary>
    public BulkOperationStatus Status { get; init; }
    /// <summary>The filter used.</summary>
    public BulkOperationFilter Filter { get; init; } = new();
    /// <summary>Revocation reason, if any.</summary>
    public string? Reason { get; init; }
    /// <summary>Who previewed it.</summary>
    public string CreatedBy { get; init; } = string.Empty;
    /// <summary>Stable subject of the creator, if known.</summary>
    public string? CreatedBySubject { get; init; }
    /// <summary>When it was previewed (UTC).</summary>
    public DateTime CreatedAtUtc { get; init; }
    /// <summary>Who executed it.</summary>
    public string? ExecutedBy { get; init; }
    /// <summary>When execute was accepted (UTC).</summary>
    public DateTime? ExecutedAtUtc { get; init; }
    /// <summary>When the run finished (UTC).</summary>
    public DateTime? FinishedAtUtc { get; init; }
    /// <summary>Items frozen at preview.</summary>
    public int ItemCount { get; init; }
    /// <summary>Items done.</summary>
    public int DoneCount { get; init; }
    /// <summary>Items skipped.</summary>
    public int SkippedCount { get; init; }
    /// <summary>Items failed.</summary>
    public int FailedCount { get; init; }
    /// <summary>Matched requests left out at preview, by reason (<c>not-issued</c>, <c>active-renewal</c>, <c>ca-capable</c>, <c>client-key</c>).</summary>
    public IReadOnlyDictionary<string, int> Excluded { get; init; } = new Dictionary<string, int>();
}

/// <summary>One item as clients see it, with the common name of its request.</summary>
public sealed class BulkOperationItemView
{
    /// <summary>The certificate request acted on.</summary>
    public CertificateRequestId RequestId { get; init; }
    /// <summary>Its common name, or empty if the request no longer exists.</summary>
    public string CommonName { get; init; } = string.Empty;
    /// <summary>Result.</summary>
    public BulkItemOutcome Outcome { get; init; }
    /// <summary>Why skipped or failed.</summary>
    public string? Detail { get; init; }
    /// <summary>For renew: the new request.</summary>
    public CertificateRequestId? ResultRequestId { get; init; }
}

/// <summary>Response to a preview: the operation plus the first few items.</summary>
public sealed class BulkOperationPreview
{
    /// <summary>The new operation, in <see cref="BulkOperationStatus.Previewed"/>.</summary>
    public BulkOperationView Operation { get; init; } = new();
    /// <summary>The first items, for a quick look; the full list is paged at <c>/items</c>.</summary>
    public IReadOnlyList<BulkOperationItemView> Sample { get; init; } = [];
}
