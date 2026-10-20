using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Qertum.Services;

/// <summary>
/// Guarded access to the CRL cache. Redis can be down or slow; the CRL can always be rebuilt from the
/// database, so a failed cache call is logged and reported, never allowed to fail a CRL request.
/// Cancellation is not a cache failure and still propagates.
/// </summary>
public static class CrlCacheExtensions
{
    /// <summary>The cached bytes of <paramref name="key"/>, or null when absent or when the cache could not be read.</summary>
    public static async Task<byte[]?> TryGetAsync(this IDistributedCache cache, string key, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            return await cache.GetAsync(key, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The CRL cache could not be read for {Key}; building from the database instead.", key);
            return null;
        }
    }

    /// <summary>Caches <paramref name="value"/>; false when the cache could not be written.</summary>
    public static async Task<bool> TrySetAsync(this IDistributedCache cache, string key, byte[] value,
        DistributedCacheEntryOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            await cache.SetAsync(key, value, options, cancellationToken);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The CRL cache could not be written for {Key}; the CRL is still served.", key);
            return false;
        }
    }

    /// <summary>Drops <paramref name="key"/>; false when the cache could not be reached.</summary>
    public static async Task<bool> TryRemoveAsync(this IDistributedCache cache, string key, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            await cache.RemoveAsync(key, cancellationToken);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "The CRL cache could not drop {Key}.", key);
            return false;
        }
    }
}
