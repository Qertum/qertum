namespace Qertum.Services.Lifecycle;

/// <summary>
/// Records operational events (a challenge retry, a refused login) in <c>LifecycleEvents</c> only.
/// Never in the audit file: these are not actions someone performed. At most
/// <see cref="DiagnosticFloodLimiter.DefaultPerMinute"/> events per subject per minute are kept; the
/// first one over the limit becomes a single <c>EventsSuppressed</c> row.
/// </summary>
/// <remarks>Never pass a token, key authorization, password or other ownership proof in any argument.</remarks>
public interface IDiagnosticEventLog
{
    void Record(string subjectType, Guid subjectId, string action, string performedBy,
        string? category = null, string? detail = null, object? data = null);
}
