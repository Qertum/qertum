using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.Approvals;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.BulkOperations;

namespace Qertum.QueueConsumer;

/// <summary>Runs <see cref="WellKnownJobTypes.BulkOperation"/>: hands the operation id in the payload to <see cref="BulkOperationRunner"/>.</summary>
internal sealed class BulkOperationJobHandler(BulkOperationRunner runner, ICertificateRevocationQueue revocationQueue) : IBackgroundJobHandler
{
    public string JobType => WellKnownJobTypes.BulkOperation;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        using var payload = JsonDocument.Parse(job.PayloadJson ?? "{}");
        if (!payload.RootElement.TryGetProperty("operationId", out var raw) || !Guid.TryParse(raw.GetString(), out var id))
            throw new InvalidOperationException("The bulk operation job has no operationId.");

        var summary = await runner.RunAsync(new BulkOperationId(id), cancellationToken);
        revocationQueue.TrySignal(); // wake the consumer once for the whole batch of PendingRevocation rows
        return summary;
    }
}

/// <summary>Runs <see cref="WellKnownJobTypes.ApprovalRetention"/>: expires stale approval requests and deletes finished ones past <c>Approvals:RetentionDays</c>.</summary>
internal sealed class ApprovalRetentionJobHandler(ApprovalSweeper sweeper) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "approval-retention";
    public const string RequestedBy = "approval-retention-scheduler";

    public static IntervalJob Schedule { get; } = new(
        WellKnownJobTypes.ApprovalRetention, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.FromMinutes(5), Interval: TimeSpan.FromHours(1));

    public string JobType => WellKnownJobTypes.ApprovalRetention;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var (expired, deleted) = await sweeper.RunAsync(cancellationToken);
        return $"expired={expired}, deleted={deleted}";
    }
}

/// <summary>Runs <see cref="WellKnownJobTypes.BulkOperationRetention"/>: deletes finished operations past <c>BulkOperations:RetentionDays</c>; their items go with them (cascade).</summary>
internal sealed class BulkOperationRetentionJobHandler(
    CertificateRequestDbContext db,
    IOptions<BulkOperationsOptions> options,
    TimeProvider? timeProvider = null) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "bulk-operation-retention";
    public const string RequestedBy = "bulk-operation-retention-scheduler";

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public static IntervalJob Schedule { get; } = new(
        WellKnownJobTypes.BulkOperationRetention, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.FromMinutes(5), Interval: TimeSpan.FromHours(24));

    public string JobType => WellKnownJobTypes.BulkOperationRetention;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var cutoff = _clock.GetUtcNow().UtcDateTime.AddDays(-options.Value.RetentionDays);
        var finished = new[] { BulkOperationStatus.Completed, BulkOperationStatus.CompletedWithErrors, BulkOperationStatus.Cancelled, BulkOperationStatus.Expired };
        var ids = await db.BulkOperations.Where(o => finished.Contains(o.Status) && o.CreatedAtUtc < cutoff)
            .Select(o => o.Id).ToListAsync(cancellationToken);
        if (ids.Count == 0) return "operations=0";
        // Child-first: ExecuteDelete bypasses the tracker, and SQLite only cascades with foreign_keys on.
        await db.BulkOperationItems.Where(i => ids.Contains(i.OperationId)).ExecuteDeleteAsync(cancellationToken);
        await db.BulkOperations.Where(o => ids.Contains(o.Id)).ExecuteDeleteAsync(cancellationToken);
        return $"operations={ids.Count}";
    }
}
