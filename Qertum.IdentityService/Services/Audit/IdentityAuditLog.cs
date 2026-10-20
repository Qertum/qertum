using System.Diagnostics;
using Serilog;
using Serilog.Formatting.Compact;

namespace Qertum.IdentityService.Services.Audit;

/// <summary>
/// Writes audit events as CLEF through a dedicated Serilog logger, not the application's logging
/// pipeline, with the same properties as the CA's audit log so the same tooling reads both.
/// </summary>
public sealed class IdentityAuditLog : IIdentityAuditLog, IDisposable
{
    private readonly Serilog.Core.Logger _log;
    private readonly Qertum.Audit.AuditChain _chain;
    private readonly Microsoft.Extensions.Logging.ILogger<IdentityAuditLog> _logger;

    public IdentityAuditLog(string? path, Microsoft.Extensions.Logging.ILogger<IdentityAuditLog> logger)
    {
        _logger = logger;
        var config = new LoggerConfiguration();
        if (!string.IsNullOrEmpty(path))
        {
            config = config.WriteTo.File(
                formatter: new CompactJsonFormatter(),
                path: path,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 365,
                shared: true);
        }

        _log = config.CreateLogger();
        _chain = new Qertum.Audit.AuditChain(Qertum.Audit.AuditChain.DefaultWriter(), Qertum.Audit.AuditLogFiles.NewestFirst(path));
    }

    public void Write(string action, string performedBy, Guid? resourceId = null, string? resourceName = null, string? detail = null)
    {
        try
        {
            // One format for both audit logs (Qertum.Audit), so the same tooling reads either file.
            _chain.Write(_log, action, performedBy, resourceId, resourceName, detail);
        }
        catch (Exception ex)
        {
            // The change already happened; failing to record it must not undo or hide it.
            Microsoft.Extensions.Logging.LoggerExtensions.LogWarning(_logger, ex, "Failed to write identity audit entry {Action}.", action);
        }
    }

    public void Dispose() => _log.Dispose();
}
