using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Services.Lifecycle;
using Serilog;
using Serilog.Configuration;
using Serilog.Formatting.Compact;

namespace Qertum.Services;

/// <summary>
/// Serilog-backed audit log service. Each audit event is written once and fanned out by Serilog to
/// two sinks: the rolling CLEF file (the write-only record; forwarding it to a SIEM is a log agent's
/// job) and <see cref="LifecycleEventTableSink"/>, an indexed copy for reading timelines.
/// </summary>
public sealed class SerilogAuditLogService : IAuditLogService, IDiagnosticEventLog, IDisposable
{
    private readonly Serilog.Core.Logger _log;
    private readonly AuditLogFileReader _reader;
    private readonly Serilog.Core.Logger _diagnostic;
    private readonly DiagnosticFloodLimiter _flood;
    private readonly Qertum.Audit.AuditChain? _chain;

    public SerilogAuditLogService(
        IOptions<AuditLogOptions> options,
        AuditLogFileReader reader,
        IServiceScopeFactory scopeFactory,
        IOptions<LifecycleEventsOptions> lifecycleOptions,
        TimeProvider time,
        Qertum.Audit.AuditChain? chain = null)
    {
        _reader = reader;
        _chain = chain;
        var table = new LifecycleEventTableSink(scopeFactory);
        var batching = new BatchingOptions
        {
            BufferingTimeLimit = TimeSpan.FromMilliseconds(lifecycleOptions.Value.BufferingTimeLimitMs),
            BatchSizeLimit = 200,
            QueueLimit = 10_000,
        };
        _log = BuildLogger(options.Value).WriteTo.Sink(table, batching).CreateLogger();
        // Table only: diagnostics must never reach the write-only audit file.
        _diagnostic = new LoggerConfiguration().WriteTo.Sink(table, batching).CreateLogger();
        _flood = new DiagnosticFloodLimiter(time, DiagnosticFloodLimiter.DefaultPerMinute);
    }

    private static LoggerConfiguration BuildLogger(AuditLogOptions opts)
    {
        var config = new LoggerConfiguration();

        if (opts.File.Enabled && !string.IsNullOrEmpty(opts.File.Path))
        {
            var rollingInterval = Enum.TryParse<RollingInterval>(opts.File.RollingInterval, ignoreCase: true, out var ri)
                ? ri
                : RollingInterval.Day;

            config = config.WriteTo.File(
                formatter: new CompactJsonFormatter(),
                path: opts.File.Path,
                rollingInterval: rollingInterval,
                retainedFileCountLimit: opts.File.RetainedFileCountLimit,
                shared: true); // shared: true allows concurrent writes from ApiService and QueueConsumer
        }

        return config;
    }

    /// <inheritdoc />
    public Task LogAsync(
        string action,
        string performedBy,
        Guid? resourceId = null,
        string? resourceName = null,
        string? detail = null,
        CancellationToken cancellationToken = default)
    {
        // One format for both audit logs (Qertum.Audit), so the same tooling reads either file.
        // Chained when the host registered a chain; tests that build the service directly keep the unchained write.
        // Names and details can come from request bodies: one line each, before the chain hashes them.
        resourceName = SingleLine(resourceName);
        detail = SingleLine(detail);
        if (_chain is not null)
            _chain.Write(_log, action, performedBy, resourceId, resourceName, detail);
        else
            Qertum.Audit.AuditEventFormat.Write(_log, action, performedBy, resourceId, resourceName, detail);

        return Task.CompletedTask;
    }

    /// <summary>Line breaks become spaces, so a value cannot start what looks like another log line.</summary>
    internal static string? SingleLine(string? value) =>
        value?.Replace("\r\n", " ").Replace("\r", " ").Replace("\n", " ");

    /// <inheritdoc />
    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(
        int page = 1,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
        => _reader.ReadAsync(page, pageSize, cancellationToken);

    /// <inheritdoc />
    public void Record(string subjectType, Guid subjectId, string action, string performedBy,
        string? category = null, string? detail = null, object? data = null)
    {
        switch (_flood.Admit(subjectType, subjectId))
        {
            case FloodAdmission.Dropped:
                return;
            case FloodAdmission.SuppressedMarker:
                action = "EventsSuppressed";
                category = null;
                detail = $"More than {DiagnosticFloodLimiter.DefaultPerMinute} events for this subject in one minute; the rest of that minute is not recorded.";
                data = null;
                break;
        }

        _diagnostic
            .ForContext("IsDiagnosticEvent", true)
            .ForContext("EventId", Guid.NewGuid())
            .ForContext("SubjectType", subjectType)
            .ForContext("SubjectId", subjectId)
            .ForContext("Action", action)
            .ForContext("PerformedBy", performedBy)
            .ForContext("Category", category)
            .ForContext("Detail", detail)
            .ForContext("DataJson", data is null ? null : JsonSerializer.Serialize(data))
            .ForContext("TraceId", Activity.Current?.TraceId.ToString())
            .Information("Diagnostic {Action}", action);
    }

    /// <summary>Disposing flushes both loggers, including any batch still buffered for the table.</summary>
    public void Dispose()
    {
        _log.Dispose();
        _diagnostic.Dispose();
    }
}
