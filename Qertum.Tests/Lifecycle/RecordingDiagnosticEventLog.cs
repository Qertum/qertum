using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

/// <summary>
/// Captures diagnostic events in memory instead of writing them. Public because the public
/// <c>EstTestFactory</c> exposes one.
/// </summary>
public sealed class RecordingDiagnosticEventLog : IDiagnosticEventLog
{
    public sealed record Entry(string SubjectType, Guid SubjectId, string Action, string PerformedBy,
        string? Category, string? Detail, object? Data);

    private readonly List<Entry> _entries = [];

    public IReadOnlyList<Entry> Entries
    {
        get { lock (_entries) return [.. _entries]; }
    }

    public void Record(string subjectType, Guid subjectId, string action, string performedBy,
        string? category = null, string? detail = null, object? data = null)
    {
        lock (_entries) _entries.Add(new Entry(subjectType, subjectId, action, performedBy, category, detail, data));
    }
}
