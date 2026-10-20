using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Qertum.Services.Policies;

namespace Qertum.Services.BulkOperations;

/// <summary>
/// Works through the pending items of a running <see cref="BulkOperation"/>, one at a time, through
/// <see cref="IBulkItemActions"/>. Resume-safe: it only takes <see cref="BulkItemOutcome.Pending"/> items
/// and records each outcome with an untracked update, so a crash repeats nothing that finished. All of its
/// own writes are <c>ExecuteUpdate</c>, which lets it clear the shared change tracker after any item that
/// threw without losing bookkeeping.
/// </summary>
public sealed class BulkOperationRunner(
    CertificateRequestDbContext db,
    IBulkItemActions actions,
    IAuditLogService auditLog,
    IWebhookService webhooks,
    ILogger<BulkOperationRunner> logger,
    TimeProvider? timeProvider = null)
{
    private const int Batch = 100;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Runs the operation to a final status and returns a short summary for the job result.</summary>
    /// <param name="id">The operation.</param>
    /// <param name="ct">Cancellation; cancelling leaves the operation <c>Running</c> for the retry.</param>
    /// <returns>A one-line summary.</returns>
    public async Task<string> RunAsync(BulkOperationId id, CancellationToken ct)
    {
        var operation = await db.BulkOperations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == id, ct);
        if (operation is null) return "skipped: no such operation";
        if (operation.Status != BulkOperationStatus.Running) return $"skipped: not running ({operation.Status})";

        var caller = ReadCaller(operation);
        var performedBy = operation.ExecutedBy ?? operation.CreatedBy;
        var now = _clock.GetUtcNow().UtcDateTime;
        await db.BulkOperations.Where(o => o.Id == id && o.StartedAtUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.StartedAtUtc, now), ct);

        while (true)
        {
            var batch = await db.BulkOperationItems.AsNoTracking()
                .Where(i => i.OperationId == id && i.Outcome == BulkItemOutcome.Pending)
                .OrderBy(i => i.RequestId).Take(Batch).Select(i => i.RequestId).ToListAsync(ct);
            if (batch.Count == 0) break;

            foreach (var requestId in batch)
            {
                ct.ThrowIfCancellationRequested();
                var (outcome, detail, result) = await ProcessAsync(operation, requestId, performedBy, caller, ct);
                // Not the run's token: an action that already succeeded must have its outcome stored even if the
                // host is stopping, or the retry would repeat it.
                await db.BulkOperationItems.Where(i => i.OperationId == id && i.RequestId == requestId)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(i => i.Outcome, outcome)
                        .SetProperty(i => i.Detail, detail)
                        .SetProperty(i => i.ResultRequestId, result), CancellationToken.None);
            }
            await RecountAsync(id, ct);
        }

        return await FinishAsync(id, ct);
    }

    private async Task<(BulkItemOutcome Outcome, string? Detail, CertificateRequestId? Result)> ProcessAsync(
        BulkOperation operation, CertificateRequestId requestId, string performedBy, CallerContext caller, CancellationToken ct)
    {
        try
        {
            if (operation.Kind == BulkOperationKind.Revoke)
            {
                return await actions.RevokeAsync(requestId, operation.Reason ?? "bulk revoke", performedBy, ct)
                    ? (BulkItemOutcome.Done, null, null)
                    : (BulkItemOutcome.Skipped, "No longer Issued.", null);
            }

            // RenewAsync accepts any status and never looks for an existing renewal, so the run re-checks what the
            // preview checked: the source must still be Issued and must not have gained a renewal since.
            var status = await db.CertificateRequests.AsNoTracking().Where(r => r.Id == requestId)
                .Select(r => (CertificateRequestStatus?)r.Status).SingleOrDefaultAsync(ct);
            if (status != CertificateRequestStatus.Issued)
                return (BulkItemOutcome.Skipped, "No longer Issued.", null);
            var hasRenewal = await db.CertificateRequests.AsNoTracking().AnyAsync(c => c.RenewedFromId == requestId
                && c.Status != CertificateRequestStatus.Rejected && c.Status != CertificateRequestStatus.Revoked, ct);
            if (hasRenewal)
                return (BulkItemOutcome.Skipped, "A renewal already exists.", null);

            var renewal = await actions.RenewAsync(requestId, performedBy, caller, ct);
            return (BulkItemOutcome.Done, null, renewal);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // The single-item path may have left half-tracked rows behind; nothing here depends on the tracker.
            db.ChangeTracker.Clear();
            logger.LogWarning(ex, "Bulk operation {OperationId}: item {RequestId} failed.", operation.Id, requestId);
            var detail = ex.Message.Length > 900 ? ex.Message[..900] : ex.Message;
            return (BulkItemOutcome.Failed, detail, null);
        }
    }

    private async Task RecountAsync(BulkOperationId id, CancellationToken ct)
    {
        var counts = await db.BulkOperationItems.AsNoTracking().Where(i => i.OperationId == id)
            .GroupBy(i => i.Outcome).Select(g => new { Outcome = g.Key, Count = g.Count() }).ToListAsync(ct);
        int Of(BulkItemOutcome o) => counts.FirstOrDefault(c => c.Outcome == o)?.Count ?? 0;
        var (done, skipped, failed) = (Of(BulkItemOutcome.Done), Of(BulkItemOutcome.Skipped), Of(BulkItemOutcome.Failed));
        await db.BulkOperations.Where(o => o.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(o => o.DoneCount, done).SetProperty(o => o.SkippedCount, skipped).SetProperty(o => o.FailedCount, failed), ct);
    }

    private async Task<string> FinishAsync(BulkOperationId id, CancellationToken ct)
    {
        await RecountAsync(id, ct);
        var operation = await db.BulkOperations.AsNoTracking().SingleAsync(o => o.Id == id, ct);
        var status = operation.FailedCount > 0 ? BulkOperationStatus.CompletedWithErrors : BulkOperationStatus.Completed;
        var now = _clock.GetUtcNow().UtcDateTime;

        // Only the run that flips Running to a final status reports it, so a re-run audits nothing twice.
        var flipped = await db.BulkOperations.Where(o => o.Id == id && o.Status == BulkOperationStatus.Running)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, status).SetProperty(o => o.FinishedAtUtc, now), ct);

        var summary = string.Create(CultureInfo.InvariantCulture,
            $"items={operation.ItemCount}, done={operation.DoneCount}, skipped={operation.SkippedCount}, failed={operation.FailedCount}");
        if (flipped == 0) return summary;

        var performedBy = operation.ExecutedBy ?? operation.CreatedBy;
        await auditLog.LogAsync("BulkOperationCompleted", performedBy, (Guid)id, operation.Kind.ToString(),
            $"Status: {status}; {summary}", ct);
        await webhooks.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.BulkOperationCompleted, (Guid)id, operation.Kind.ToString(), PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["operationId"] = id.ToString(),
                ["kind"] = operation.Kind.ToString(),
                ["status"] = status.ToString(),
                ["itemCount"] = operation.ItemCount.ToString(CultureInfo.InvariantCulture),
                ["doneCount"] = operation.DoneCount.ToString(CultureInfo.InvariantCulture),
                ["skippedCount"] = operation.SkippedCount.ToString(CultureInfo.InvariantCulture),
                ["failedCount"] = operation.FailedCount.ToString(CultureInfo.InvariantCulture)
            }), ct);
        return summary;
    }

    private static CallerContext ReadCaller(BulkOperation operation)
    {
        var snapshot = operation.CallerSnapshotJson is { } json
            ? JsonSerializer.Deserialize<BulkCallerSnapshot>(json, Json)
            : null;
        return snapshot is null
            ? new CallerContext(null, operation.ExecutedBy ?? operation.CreatedBy, IsAdmin: false, HoldsCaPermission: false)
            : new CallerContext(snapshot.Subject, snapshot.Name, snapshot.IsAdmin, snapshot.HoldsCaPermission);
    }
}
