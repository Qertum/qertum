using System.Collections.Concurrent;

namespace Qertum.Services.Lifecycle;

/// <summary>What <see cref="DiagnosticFloodLimiter.Admit"/> decided for one event.</summary>
public enum FloodAdmission
{
    Admitted,

    /// <summary>The first event over the limit: record one "suppressed" marker in its place.</summary>
    SuppressedMarker,

    Dropped
}

/// <summary>
/// Fixed one-minute windows per subject, so guessing passwords against one EST credential cannot
/// fill the table. In memory and per process: a limit, not an accounting.
/// </summary>
public sealed class DiagnosticFloodLimiter(TimeProvider time, int perMinute)
{
    public const int DefaultPerMinute = 20;
    private const int PruneThreshold = 10_000;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<(string SubjectType, Guid SubjectId), Counter> _counters = new();

    public FloodAdmission Admit(string subjectType, Guid subjectId)
    {
        var now = time.GetUtcNow();
        if (_counters.Count > PruneThreshold)
            foreach (var (key, _) in _counters.Where(kv => now - kv.Value.Start >= Window).ToList())
                _counters.TryRemove(key, out _);

        var counter = _counters.GetOrAdd((subjectType, subjectId), _ => new Counter { Start = now });
        lock (counter)
        {
            if (now - counter.Start >= Window)
            {
                counter.Start = now;
                counter.Count = 0;
            }

            counter.Count++;
            if (counter.Count <= perMinute) return FloodAdmission.Admitted;
            return counter.Count == perMinute + 1 ? FloodAdmission.SuppressedMarker : FloodAdmission.Dropped;
        }
    }

    private sealed class Counter
    {
        public DateTimeOffset Start;
        public int Count;
    }
}
