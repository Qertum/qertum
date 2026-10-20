namespace Qertum.Services.BackgroundJobs;

/// <summary>
/// The durable background job queue in <c>BackgroundJobs</c>. Every state change records one
/// diagnostic event (subject <c>BackgroundJob</c>) and one operational log line, so a job's history
/// can be followed without handler code.
/// </summary>
public interface IBackgroundJobQueue
{
    /// <summary>
    /// Inserts a <see cref="BackgroundJobStatus.Pending"/> job due now. Returns null, recording
    /// nothing, when another pending or processing job already holds <paramref name="concurrencyKey"/>.
    /// </summary>
    Task<BackgroundJob?> EnqueueAsync(string jobType, string? concurrencyKey, string requestedBy, string? reason,
        string? payloadJson = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically claims the oldest due pending job of one of <paramref name="handledJobTypes"/>,
    /// marking it processing and counting the attempt. Null when nothing is due.
    /// </summary>
    Task<BackgroundJob?> ClaimNextAsync(IReadOnlyCollection<string> handledJobTypes, CancellationToken cancellationToken = default);

    /// <summary>Marks a claimed job completed with its handler's result summary.</summary>
    Task CompleteAsync(BackgroundJob job, string? result, CancellationToken cancellationToken = default);

    /// <summary>Returns a claimed job to pending, not claimable before <paramref name="nextAttemptAfterUtc"/>.</summary>
    Task ScheduleRetryAsync(BackgroundJob job, string error, DateTime nextAttemptAfterUtc, CancellationToken cancellationToken = default);

    /// <summary>Marks a claimed job failed; its concurrency key is released.</summary>
    Task FailAsync(BackgroundJob job, string error, CancellationToken cancellationToken = default);

    /// <summary>Returns every processing job to pending (a processor stopped mid-run). Returns how many.</summary>
    Task<int> RecoverStuckAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns processing jobs claimed before <paramref name="claimedBeforeUtc"/> to pending: a claim
    /// whose completion bookkeeping never ran would otherwise hold its concurrency key until restart.
    /// </summary>
    Task<int> RecoverStaleAsync(DateTime claimedBeforeUtc, CancellationToken cancellationToken = default);

    /// <summary>Deletes completed and failed jobs that finished before <paramref name="cutoffUtc"/>. Returns how many.</summary>
    Task<int> DeleteFinishedBeforeAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default);
}
