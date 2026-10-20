using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Lifecycle;

namespace Qertum.QueueConsumer;

/// <summary>
/// Runs <see cref="WellKnownJobTypes.LifecycleEventRetention"/>: deletes diagnostic rows after
/// <c>LifecycleEvents:DiagnosticRetentionDays</c> and audit rows once the audit files they copy have
/// been rolled away. Runs in the queue consumer only, so instances of the other hosts do not race it.
/// </summary>
internal sealed class LifecycleEventRetentionJobHandler(
    CertificateRequestDbContext db,
    IOptions<LifecycleEventsOptions> options,
    IOptions<AuditLogOptions> auditOptions,
    TimeProvider time,
    ILogger<LifecycleEventRetentionJobHandler> logger) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "lifecycle-event-retention";
    public const string RequestedBy = "lifecycle-event-retention-scheduler";

    /// <summary>Same schedule as the timer it replaced: at start, then daily.</summary>
    public static readonly IntervalJob Schedule = new(
        WellKnownJobTypes.LifecycleEventRetention, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.Zero, Interval: TimeSpan.FromDays(1));

    public string JobType => WellKnownJobTypes.LifecycleEventRetention;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var (diagnostic, audit) = await SweepAsync(cancellationToken);
        return $"diagnostic={diagnostic}, audit={audit}";
    }

    internal async Task<(int Diagnostic, int Audit)> SweepAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;

        var diagnosticCutoff = now.AddDays(-options.Value.DiagnosticRetentionDays);
        var diagnostic = await db.LifecycleEvents
            .Where(e => e.Kind == LifecycleEventKinds.Diagnostic && e.OccurredAtUtc < diagnosticCutoff)
            .ExecuteDeleteAsync(ct);

        var audit = 0;
        if (AuditRetention.WindowFor(auditOptions.Value) is { } window)
        {
            var auditCutoff = now - window;
            audit = await db.LifecycleEvents
                .Where(e => e.Kind == LifecycleEventKinds.Audit && e.OccurredAtUtc < auditCutoff)
                .ExecuteDeleteAsync(ct);
        }

        if (diagnostic + audit > 0)
            logger.LogInformation("Lifecycle event retention removed {Diagnostic} diagnostic and {Audit} audit rows.",
                diagnostic, audit);
        return (diagnostic, audit);
    }
}
