using System.Globalization;
using System.Text.Json;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.QueueConsumer;

/// <summary>Runs <see cref="WellKnownJobTypes.AuditCheckpoint"/>: reads every audit chain head and sends one webhook event.</summary>
internal sealed class AuditCheckpointJobHandler(AuditCheckpointReader reader, IWebhookService webhooks) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "audit-checkpoint";
    public const string RequestedBy = "audit-checkpoint-scheduler";

    /// <summary>First checkpoint three minutes after start, then every <c>AuditLog:Checkpoint:IntervalMinutes</c>; off when disabled.</summary>
    public static IntervalJob Schedule(AuditLogOptions.CheckpointOptions options) => new(
        WellKnownJobTypes.AuditCheckpoint, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.FromMinutes(3),
        Interval: TimeSpan.FromMinutes(options.IntervalMinutes),
        Enabled: options.Enabled);

    public string JobType => WellKnownJobTypes.AuditCheckpoint;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var checkpoint = reader.Read();
        if (checkpoint.Chains.Count == 0)
            return "skipped: no chained audit entries";

        var heads = JsonSerializer.Serialize(checkpoint.Chains.Select(c => new { writer = c.Writer, seq = c.Seq, hash = c.Hash }));
        // Not the swallowing enqueue: a lost delivery must retry, or the receiver's anchor silently goes stale.
        await webhooks.EnqueueEventOrThrowAsync(new WebhookEvent(
            WellKnownWebhookEvents.AuditCheckpoint, PerformedBy: RequestedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["generatedAt"] = checkpoint.GeneratedAtUtc.ToString("O", CultureInfo.InvariantCulture),
                ["chainCount"] = checkpoint.Chains.Count.ToString(CultureInfo.InvariantCulture),
                ["heads"] = heads
            }), cancellationToken);
        return $"chains={checkpoint.Chains.Count}";
    }
}
