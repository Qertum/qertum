namespace Qertum.Services;

public interface IAuditLogService
{
    /// <summary>
    /// Records a single audit event.
    /// </summary>
    Task LogAsync(
        string action,
        string performedBy,
        Guid? resourceId = null,
        string? resourceName = null,
        string? detail = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns all audit log entries, newest first.
    /// </summary>
    Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(
        int page = 1,
        int pageSize = 100,
        CancellationToken cancellationToken = default);
}
