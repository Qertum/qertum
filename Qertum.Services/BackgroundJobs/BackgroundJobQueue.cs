using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Qertum.Services.Lifecycle;

namespace Qertum.Services.BackgroundJobs;

/// <inheritdoc />
public sealed class BackgroundJobQueue(
    CertificateRequestDbContext dbContext,
    IDiagnosticEventLog diagnostics,
    ILogger<BackgroundJobQueue> logger,
    TimeProvider? timeProvider = null) : IBackgroundJobQueue
{
    /// <summary><c>performedBy</c> for every action after the job is queued.</summary>
    public const string ProcessorIdentity = "queue-consumer";

    public const int MaxResultLength = 500;
    public const int MaxFailureReasonLength = 2000;

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<BackgroundJob?> EnqueueAsync(string jobType, string? concurrencyKey, string requestedBy,
        string? reason, string? payloadJson = null, CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var job = new BackgroundJob
        {
            JobType = jobType,
            ConcurrencyKey = concurrencyKey,
            RequestedBy = requestedBy,
            Reason = reason,
            PayloadJson = payloadJson,
            RequestedAtUtc = now,
            NextAttemptAfterUtc = now
        };
        dbContext.BackgroundJobs.Add(job);
        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        // Detected from the filtered unique index, never by a pre-check: two producers racing both
        // pass a check, only one passes the index.
        catch (DbUpdateException ex) when (IsActiveConcurrencyKeyConflict(ex))
        {
            dbContext.Entry(job).State = EntityState.Detached;
            logger.LogDebug("Background job {JobType} not queued: a job with key {ConcurrencyKey} is already active.",
                jobType, concurrencyKey);
            return null;
        }
        dbContext.Entry(job).State = EntityState.Detached;

        Record(job, DiagnosticActions.JobQueued, requestedBy, reason);
        logger.LogInformation("Background job {JobId} ({JobType}) queued by {RequestedBy}: {Reason}",
            job.Id, jobType, requestedBy, reason);
        return job;
    }

    public async Task<BackgroundJob?> ClaimNextAsync(IReadOnlyCollection<string> handledJobTypes,
        CancellationToken cancellationToken = default)
    {
        var types = handledJobTypes.ToArray();
        if (types.Length == 0) return null;

        while (!cancellationToken.IsCancellationRequested)
        {
            var now = _clock.GetUtcNow().UtcDateTime;
            // AsNoTracking: the claim is an ExecuteUpdateAsync the change tracker never sees (see
            // CertificateRequestService.DequeueNextApprovedAsync).
            var next = await dbContext.BackgroundJobs
                .AsNoTracking()
                .Where(j => j.Status == BackgroundJobStatus.Pending && j.NextAttemptAfterUtc <= now && types.Contains(j.JobType))
                .OrderBy(j => j.NextAttemptAfterUtc)
                .ThenBy(j => j.RequestedAtUtc)
                .FirstOrDefaultAsync(cancellationToken);
            if (next is null) return null;

            var claimed = await dbContext.BackgroundJobs
                .Where(j => j.Id == next.Id && j.Status == BackgroundJobStatus.Pending)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(j => j.Status, BackgroundJobStatus.Processing)
                    .SetProperty(j => j.ClaimedAtUtc, now)
                    .SetProperty(j => j.AttemptCount, j => j.AttemptCount + 1),
                    cancellationToken);
            if (claimed == 0) continue;

            var job = await dbContext.BackgroundJobs.AsNoTracking().SingleAsync(j => j.Id == next.Id, cancellationToken);
            Record(job, DiagnosticActions.JobClaimed, ProcessorIdentity, $"attempt {job.AttemptCount}");
            logger.LogInformation("Background job {JobId} ({JobType}) claimed, attempt {Attempt}.",
                job.Id, job.JobType, job.AttemptCount);
            return job;
        }
        return null;
    }

    public async Task CompleteAsync(BackgroundJob job, string? result, CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var summary = Truncate(result, MaxResultLength);
        await dbContext.BackgroundJobs
            .Where(j => j.Id == job.Id && j.Status == BackgroundJobStatus.Processing)
            .ExecuteUpdateAsync(s => s
                .SetProperty(j => j.Status, BackgroundJobStatus.Completed)
                .SetProperty(j => j.CompletedAtUtc, now)
                .SetProperty(j => j.Result, summary)
                .SetProperty(j => j.FailureReason, (string?)null),
                cancellationToken);
        Record(job, DiagnosticActions.JobCompleted, ProcessorIdentity, summary);
        logger.LogInformation("Background job {JobId} ({JobType}) completed: {Result}", job.Id, job.JobType, summary);
    }

    public async Task ScheduleRetryAsync(BackgroundJob job, string error, DateTime nextAttemptAfterUtc,
        CancellationToken cancellationToken = default)
    {
        var reason = Truncate(error, MaxFailureReasonLength);
        await dbContext.BackgroundJobs
            .Where(j => j.Id == job.Id && j.Status == BackgroundJobStatus.Processing)
            .ExecuteUpdateAsync(s => s
                .SetProperty(j => j.Status, BackgroundJobStatus.Pending)
                .SetProperty(j => j.NextAttemptAfterUtc, nextAttemptAfterUtc)
                .SetProperty(j => j.FailureReason, reason),
                cancellationToken);
        Record(job, DiagnosticActions.JobRetryScheduled, ProcessorIdentity,
            $"{reason} (next attempt after {nextAttemptAfterUtc:O})");
        logger.LogWarning("Background job {JobId} ({JobType}) attempt {Attempt} failed; retrying after {NextAttempt:O}: {Error}",
            job.Id, job.JobType, job.AttemptCount, nextAttemptAfterUtc, reason);
    }

    public async Task FailAsync(BackgroundJob job, string error, CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var reason = Truncate(error, MaxFailureReasonLength);
        await dbContext.BackgroundJobs
            .Where(j => j.Id == job.Id && j.Status == BackgroundJobStatus.Processing)
            .ExecuteUpdateAsync(s => s
                .SetProperty(j => j.Status, BackgroundJobStatus.Failed)
                .SetProperty(j => j.CompletedAtUtc, now)
                .SetProperty(j => j.FailureReason, reason),
                cancellationToken);
        Record(job, DiagnosticActions.JobFailed, ProcessorIdentity, reason);
        logger.LogError("Background job {JobId} ({JobType}) failed after {Attempts} attempt(s): {Error}",
            job.Id, job.JobType, job.AttemptCount, reason);
    }

    public Task<int> RecoverStuckAsync(CancellationToken cancellationToken = default) =>
        RecoverAsync(claimedBeforeUtc: null, "was processing when the processor stopped", cancellationToken);

    public Task<int> RecoverStaleAsync(DateTime claimedBeforeUtc, CancellationToken cancellationToken = default) =>
        RecoverAsync(claimedBeforeUtc, $"still processing after its claim at or before {claimedBeforeUtc:O}", cancellationToken);

    private async Task<int> RecoverAsync(DateTime? claimedBeforeUtc, string detail, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var query = dbContext.BackgroundJobs
            .AsNoTracking()
            .Where(j => j.Status == BackgroundJobStatus.Processing);
        if (claimedBeforeUtc is DateTime cutoff)
            query = query.Where(j => j.ClaimedAtUtc < cutoff);
        var stuck = await query.ToListAsync(cancellationToken);

        var recovered = 0;
        foreach (var job in stuck)
        {
            var rows = await dbContext.BackgroundJobs
                .Where(j => j.Id == job.Id && j.Status == BackgroundJobStatus.Processing)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(j => j.Status, BackgroundJobStatus.Pending)
                    .SetProperty(j => j.NextAttemptAfterUtc, now),
                    cancellationToken);
            if (rows == 0) continue;
            recovered++;
            Record(job, DiagnosticActions.JobRecovered, ProcessorIdentity, detail);
            logger.LogWarning("Background job {JobId} ({JobType}) {Detail}; returned to pending.",
                job.Id, job.JobType, detail);
        }
        return recovered;
    }

    public async Task<int> DeleteFinishedBeforeAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default)
    {
        var deleted = await dbContext.BackgroundJobs
            .Where(j => (j.Status == BackgroundJobStatus.Completed || j.Status == BackgroundJobStatus.Failed)
                        && j.CompletedAtUtc < cutoffUtc)
            .ExecuteDeleteAsync(cancellationToken);
        if (deleted > 0)
            logger.LogInformation("Deleted {Count} finished background job(s) older than {Cutoff:O}.", deleted, cutoffUtc);
        return deleted;
    }

    private void Record(BackgroundJob job, string action, string performedBy, string? detail) =>
        diagnostics.Record(LifecycleSubjectTypes.BackgroundJob, job.Id.Value, action, performedBy,
            detail: detail, data: new { jobType = job.JobType });

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static bool IsActiveConcurrencyKeyConflict(DbUpdateException ex) =>
        ex.InnerException?.Message.Contains("BackgroundJobs.ConcurrencyKey", StringComparison.Ordinal) == true;
}
