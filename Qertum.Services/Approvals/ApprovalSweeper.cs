using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Approvals;

/// <summary>
/// Stamps requests whose time has run out as <see cref="ApprovalStatus.Expired"/> (audited once each) and deletes finished
/// ones past <c>Approvals:RetentionDays</c>. Expiry is derived on read, so this only makes the stored state, the audit
/// trail and the webhook event catch up; a missed run changes nothing a caller can see.
/// </summary>
public sealed class ApprovalSweeper(
    CertificateRequestDbContext db,
    IOptions<ApprovalOptions> options,
    IAuditLogService auditLog,
    IWebhookService webhooks,
    TimeProvider? timeProvider = null)
{
    /// <summary>The actor written to the audit entry of an expiry.</summary>
    public const string Actor = "approval-scheduler";

    private const int BatchSize = 500;
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Expires what is due (at most one batch per run), then deletes what has aged out.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>How many rows were expired and deleted.</returns>
    public async Task<(int Expired, int Deleted)> RunAsync(CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var pendingCutoff = now.AddHours(-options.Value.RequestTtlHours);
        var due = await db.ApprovalRequests.AsNoTracking()
            .Where(a => (a.Status == ApprovalStatus.Pending && a.RequestedAtUtc <= pendingCutoff)
                        || (a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc <= now))
            .OrderBy(a => a.RequestedAtUtc).Take(BatchSize)
            .ToListAsync(cancellationToken);

        var expired = 0;
        foreach (var row in due)
        {
            // Conditional on the stored status so a decision or claim made since the read wins.
            var changed = await db.ApprovalRequests
                .Where(a => a.Id == row.Id && a.Status == row.Status)
                .ExecuteUpdateAsync(set => set.SetProperty(a => a.Status, ApprovalStatus.Expired), cancellationToken);
            if (changed == 0)
                continue;
            expired++;
            await ApprovalNotifications.PublishAsync(auditLog, webhooks, WellKnownWebhookEvents.ApprovalExpired, Actor,
                row, ApprovalStatus.Expired, cancellationToken);
        }

        var retentionCutoff = now.AddDays(-options.Value.RetentionDays);
        var deleted = await db.ApprovalRequests
            .Where(a => a.RequestedAtUtc < retentionCutoff
                        && (a.Status == ApprovalStatus.Denied || a.Status == ApprovalStatus.Used || a.Status == ApprovalStatus.Expired))
            .ExecuteDeleteAsync(cancellationToken);
        return (expired, deleted);
    }
}
