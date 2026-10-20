using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Core;
using Serilog.Events;

namespace Qertum.Services.Lifecycle;

/// <summary>
/// Serilog sink that copies audit and diagnostic events into <c>LifecycleEvents</c>. Attached with
/// Serilog's batching, so it runs off the caller's thread.
/// </summary>
/// <remarks>
/// Exceptions propagate on purpose: Serilog's <see cref="IBatchedLogEventSink"/> contract leaves
/// retries and <c>SelfLog</c> reporting to the batching infrastructure. Because batching runs
/// separately from the caller, a table failure never reaches the audited action, and the CLEF file
/// sink on the same logger is unaffected.
/// </remarks>
public sealed class LifecycleEventTableSink(IServiceScopeFactory scopeFactory) : IBatchedLogEventSink
{
    public async Task EmitBatchAsync(IReadOnlyCollection<LogEvent> batch)
    {
        var rows = batch.Select(TryMap).OfType<LifecycleEvent>().ToList();
        if (rows.Count == 0) return;

        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();

        // A retried batch may already be committed; skip what is present rather than fail on the key.
        var ids = rows.Select(r => r.Id).ToList();
        var present = (await db.LifecycleEvents.Where(e => ids.Contains(e.Id)).Select(e => e.Id).ToListAsync())
            .ToHashSet();
        db.LifecycleEvents.AddRange(rows.Where(r => !present.Contains(r.Id)));
        await db.SaveChangesAsync();
    }

    public Task OnEmptyBatchAsync() => Task.CompletedTask;

    /// <summary>The row for <paramref name="logEvent"/>, or null when it produces none.</summary>
    internal static LifecycleEvent? TryMap(LogEvent logEvent)
    {
        if (Scalar(logEvent, "IsAuditEvent") is true)
        {
            if (Scalar(logEvent, "ResourceId") is not Guid resourceId) return null;
            if (Scalar(logEvent, "Action") is not string action) return null;
            if (AuditActionSubjects.SubjectTypeOf(action) is not { } subjectType) return null;
            if (Scalar(logEvent, "AuditEntryId") is not Guid id) return null;

            return new LifecycleEvent
            {
                Id = id,
                Kind = LifecycleEventKinds.Audit,
                OccurredAtUtc = logEvent.Timestamp.UtcDateTime,
                SubjectType = subjectType,
                SubjectId = resourceId,
                Action = action,
                PerformedBy = Scalar(logEvent, "PerformedBy") as string ?? string.Empty,
                Detail = Scalar(logEvent, "Detail") as string,
                TraceId = Scalar(logEvent, "TraceId") as string,
            };
        }

        if (Scalar(logEvent, "IsDiagnosticEvent") is true)
        {
            if (Scalar(logEvent, "EventId") is not Guid id) return null;
            if (Scalar(logEvent, "SubjectType") is not string subjectType) return null;
            if (Scalar(logEvent, "SubjectId") is not Guid subjectId) return null;
            if (Scalar(logEvent, "Action") is not string action) return null;

            return new LifecycleEvent
            {
                Id = id,
                Kind = LifecycleEventKinds.Diagnostic,
                OccurredAtUtc = logEvent.Timestamp.UtcDateTime,
                SubjectType = subjectType,
                SubjectId = subjectId,
                Action = action,
                Category = Scalar(logEvent, "Category") as string,
                PerformedBy = Scalar(logEvent, "PerformedBy") as string ?? string.Empty,
                Detail = Scalar(logEvent, "Detail") as string,
                DataJson = Scalar(logEvent, "DataJson") as string,
                TraceId = Scalar(logEvent, "TraceId") as string,
            };
        }

        return null;
    }

    private static object? Scalar(LogEvent logEvent, string name) =>
        logEvent.Properties.TryGetValue(name, out var value) && value is ScalarValue scalar ? scalar.Value : null;
}
