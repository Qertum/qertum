using System.Collections.Concurrent;

namespace Qertum.Services;

/// <summary>
/// One CRL build per cache key at a time in this process. The CRL routes are anonymous, and on a cache miss (after
/// start, expiry, eviction or a cache outage) every concurrent request used to load every revoked certificate, claim a
/// CRL number and sign its own CRL: a cheap way to burn database, memory and signing CPU (AI Scan, 1.0.0-rc6). Now the
/// first request builds; the others wait, then take the CRL built while they waited, or the cache, before building.
/// </summary>
public sealed class CrlBuildGate
{
    private sealed class Entry
    {
        public readonly SemaphoreSlim Gate = new(1, 1);
        public long Generation;
        public byte[]? Last;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Returns a CRL for <paramref name="key"/>: one built by another request while this one waited, else
    /// <paramref name="fromCache"/>, else a fresh <paramref name="build"/>. A CRL built before this call started is
    /// never reused from memory, so a revocation evicted from the cache is not hidden.
    /// </summary>
    public async Task<byte[]> GetOrBuildAsync(string key, Func<Task<byte[]?>> fromCache, Func<Task<byte[]>> build,
        CancellationToken cancellationToken)
    {
        var entry = _entries.GetOrAdd(key, _ => new Entry());
        var seen = Interlocked.Read(ref entry.Generation);
        await entry.Gate.WaitAsync(cancellationToken);
        try
        {
            if (Interlocked.Read(ref entry.Generation) != seen && entry.Last is { } builtWhileWaiting)
                return builtWhileWaiting;
            if (await fromCache() is { } cached)
                return cached;
            var built = await build();
            entry.Last = built;
            Interlocked.Increment(ref entry.Generation);
            return built;
        }
        finally
        {
            entry.Gate.Release();
        }
    }
}
