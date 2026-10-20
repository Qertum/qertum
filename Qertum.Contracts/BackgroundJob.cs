namespace Qertum.Services;

/// <summary>
/// One unit of work in the durable background job queue. A producer inserts it as
/// <see cref="BackgroundJobStatus.Pending"/>; QueueConsumer claims it, runs the handler registered for
/// <see cref="JobType"/> and records the outcome. Every state change is also a diagnostic event.
/// </summary>
public sealed class BackgroundJob
{
    /// <summary>Job identifier.</summary>
    public BackgroundJobId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>Which handler runs the job; one of <see cref="WellKnownJobTypes"/>.</summary>
    public string JobType { get; set; } = string.Empty;

    /// <summary>Queue state, stored as its name.</summary>
    public BackgroundJobStatus Status { get; set; } = BackgroundJobStatus.Pending;

    /// <summary>
    /// When set, at most one <see cref="BackgroundJobStatus.Pending"/> or
    /// <see cref="BackgroundJobStatus.Processing"/> job may hold this key (filtered unique index).
    /// </summary>
    public string? ConcurrencyKey { get; set; }

    /// <summary>Optional handler-specific input as JSON.</summary>
    public string? PayloadJson { get; set; }

    /// <summary>Who or what enqueued the job, e.g. <c>crl-refresh-scheduler</c>.</summary>
    public string RequestedBy { get; set; } = string.Empty;

    /// <summary>Why the job was enqueued, for diagnostics.</summary>
    public string? Reason { get; set; }

    /// <summary>When the job was enqueued (UTC).</summary>
    public DateTime RequestedAtUtc { get; set; }

    /// <summary>When the job was last claimed (UTC).</summary>
    public DateTime? ClaimedAtUtc { get; set; }

    /// <summary>When the job reached <see cref="BackgroundJobStatus.Completed"/> or <see cref="BackgroundJobStatus.Failed"/> (UTC).</summary>
    public DateTime? CompletedAtUtc { get; set; }

    /// <summary>The job is not claimed before this time (UTC); pushed forward by retries.</summary>
    public DateTime NextAttemptAfterUtc { get; set; }

    /// <summary>How many times the job has been claimed.</summary>
    public int AttemptCount { get; set; }

    /// <summary>Short outcome summary returned by the handler, e.g. <c>crlNumber=42</c>.</summary>
    public string? Result { get; set; }

    /// <summary>Last error message, when a run failed.</summary>
    public string? FailureReason { get; set; }
}

/// <summary>Background job queue state.</summary>
public enum BackgroundJobStatus
{
    /// <summary>Waiting to be claimed once <see cref="BackgroundJob.NextAttemptAfterUtc"/> has passed.</summary>
    Pending,

    /// <summary>Claimed by a processor and running.</summary>
    Processing,

    /// <summary>Finished successfully.</summary>
    Completed,

    /// <summary>Gave up after the configured number of attempts.</summary>
    Failed
}

/// <summary>Known <see cref="BackgroundJob.JobType"/> values.</summary>
public static class WellKnownJobTypes
{
    /// <summary>Publish a fresh full CRL (and so a new delta-CRL base).</summary>
    public const string CrlRefresh = "CrlRefresh";

    /// <summary>Scan issued certificates near expiry and file their renewal requests.</summary>
    public const string AutoRenewal = "AutoRenewal";

    /// <summary>Delete lifecycle events past their diagnostic or audit retention.</summary>
    public const string LifecycleEventRetention = "LifecycleEventRetention";

    /// <summary>Delete one batch of ACME orders past expiry plus retention, with their authorizations and challenges.</summary>
    public const string AcmeExpiryCleanup = "AcmeExpiryCleanup";

    /// <summary>Process the items of one bulk revoke or renew operation.</summary>
    public const string BulkOperation = "BulkOperation";

    /// <summary>Delete finished bulk operations past their retention, with their items.</summary>
    public const string BulkOperationRetention = "BulkOperationRetention";

    /// <summary>Expire stale two-person approval requests and delete finished ones past retention.</summary>
    public const string ApprovalRetention = "ApprovalRetention";

    /// <summary>Resolve, raise, deliver and prune expiry and renewal notices.</summary>
    public const string Notices = "Notices";

    /// <summary>Send an <c>AuditCheckpoint</c> webhook with the head of every audit hash chain.</summary>
    public const string AuditCheckpoint = "AuditCheckpoint";
}
