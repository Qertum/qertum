using StackExchange.Redis;

namespace Qertum.ServiceDefaults;

/// <summary>Client settings for the shared Redis cache.</summary>
public static class QertumRedis
{
    /// <summary>
    /// Makes a down or frozen Redis fail fast. The client default waits 5 s per call and every CRL request
    /// makes several, which turned one stopped Redis into a 17 s hang and a 500. The CRL is rebuilt from
    /// the database, so a second is long enough to wait for the cache.
    /// </summary>
    public static void ApplyResilience(ConfigurationOptions options)
    {
        options.AbortOnConnectFail = false; // start without Redis and keep reconnecting in the background
        options.ConnectTimeout = 1000;
        options.SyncTimeout = 1000;
        options.AsyncTimeout = 1000;
        // While disconnected, fail a call at once instead of queueing it for the timeout: a CRL request
        // makes several cache calls, and each one waiting a second added up to about eight.
        options.BacklogPolicy = BacklogPolicy.FailFast;
    }
}
