using System.Net;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Issuers;
using Qertum.ServiceDefaults;
using StackExchange.Redis;

namespace Qertum.Tests.Issuers;

/// <summary>
/// The CRL cache lives in Redis, which can be down or slow. With Redis stopped the API used to hang for the
/// client's timeouts and answer 500, and a revocation whose cache eviction failed was never retried, so the old
/// CRL could keep being served. These tests fail the cache on purpose.
/// </summary>
public sealed class CrlCacheFailureTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>An <see cref="IDistributedCache"/> over memory that throws on every call while <see cref="Failure"/> is set.</summary>
    private sealed class FlakyCache(IDistributedCache inner) : IDistributedCache
    {
        public Exception? Failure { get; set; }
        public int Calls { get; private set; }

        private void Check() { Calls++; if (Failure is not null) throw Failure; }

        public byte[]? Get(string key) { Check(); return inner.Get(key); }
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) { Check(); return inner.GetAsync(key, token); }
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) { Check(); inner.Set(key, value, options); }
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) { Check(); return inner.SetAsync(key, value, options, token); }
        public void Refresh(string key) { Check(); inner.Refresh(key); }
        public Task RefreshAsync(string key, CancellationToken token = default) { Check(); return inner.RefreshAsync(key, token); }
        public void Remove(string key) { Check(); inner.Remove(key); }
        public Task RemoveAsync(string key, CancellationToken token = default) { Check(); return inner.RemoveAsync(key, token); }
    }

    private static FlakyCache NewCache() => new(new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())));

    private static readonly Exception RedisDown = new InvalidOperationException("Redis is down");

    private static readonly DistributedCacheEntryOptions OneHour = new() { AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1) };

    // ---- guarded access ---------------------------------------------------------------------------------

    [Fact]
    public async Task TryGet_TrySet_TryRemove_ReportAFailedCacheInsteadOfThrowing()
    {
        var cache = NewCache();
        await cache.SetAsync("k", [1], OneHour, Ct);
        cache.Failure = RedisDown;

        Assert.Null(await cache.TryGetAsync("k", NullLogger.Instance, Ct));
        Assert.False(await cache.TrySetAsync("k", [2], OneHour, NullLogger.Instance, Ct));
        Assert.False(await cache.TryRemoveAsync("k", NullLogger.Instance, Ct));
    }

    [Fact]
    public async Task TryGet_TrySet_TryRemove_StillWorkOnAHealthyCache()
    {
        var cache = NewCache();

        Assert.True(await cache.TrySetAsync("k", [7], OneHour, NullLogger.Instance, Ct));
        Assert.Equal([7], await cache.TryGetAsync("k", NullLogger.Instance, Ct));
        Assert.True(await cache.TryRemoveAsync("k", NullLogger.Instance, Ct));
        Assert.Null(await cache.TryGetAsync("k", NullLogger.Instance, Ct));
    }

    [Fact]
    public async Task TryGet_LetsCancellationThrough()
    {
        var cache = NewCache();
        cache.Failure = new OperationCanceledException();

        await Assert.ThrowsAsync<OperationCanceledException>(() => cache.TryGetAsync("k", NullLogger.Instance, Ct));
        await Assert.ThrowsAsync<OperationCanceledException>(() => cache.TryRemoveAsync("k", NullLogger.Instance, Ct));
    }

    // ---- serving ----------------------------------------------------------------------------------------

    [Fact]
    public async Task FullCrl_IsServedFromTheDatabase_WhenTheCacheIsDown()
    {
        var cache = NewCache();
        await using var host = new IssuerApiHost(services => { services.RemoveAll<IDistributedCache>(); services.AddSingleton<IDistributedCache>(cache); });
        host.Kit.InitializeLegacy();
        var serial = await host.SeedIssuedAsync(issuerId: null, host.Kit.Legacy, revoked: true, Ct);
        cache.Failure = RedisDown;

        var response = await host.Anonymous().GetAsync("/crl", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var crl = new X509CrlParser().ReadCrl(await response.Content.ReadAsByteArrayAsync(Ct));
        Assert.NotNull(crl.GetRevokedCertificate(new BigInteger(serial, 16)));
    }

    [Fact]
    public async Task DeltaCrl_IsServedFromTheDatabase_WhenTheCacheIsDown()
    {
        var cache = NewCache();
        await using var host = new IssuerApiHost(services => { services.RemoveAll<IDistributedCache>(); services.AddSingleton<IDistributedCache>(cache); });
        host.Kit.InitializeLegacy();
        await using (var db = host.Kit.Database.CreateContext())
        {
            db.Settings.Single().DeltaCrlEnabled = true;
            await db.SaveChangesAsync(Ct);
        }
        await host.SeedIssuedAsync(issuerId: null, host.Kit.Legacy, revoked: true, Ct);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync("/crl", Ct)).StatusCode); // publishes the base while the cache works
        cache.Failure = RedisDown;

        var response = await host.Anonymous().GetAsync("/crl/delta", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ---- publishing -------------------------------------------------------------------------------------

    [Fact]
    public async Task Publisher_ThrowsOnAFailedCache_WhenStrict_SoAJobRetries()
    {
        var cache = NewCache();
        await using var host = new IssuerApiHost(services => { services.RemoveAll<IDistributedCache>(); services.AddSingleton<IDistributedCache>(cache); });
        host.Kit.InitializeLegacy();
        using var scope = host.Factory.Services.CreateScope();
        var publisher = scope.ServiceProvider.GetRequiredService<CrlPublisher>();
        var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
        cache.Failure = RedisDown;

        await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.PublishFullCrlAsync(issuer, Ct));
    }

    [Fact]
    public async Task Publisher_PublishesAndRecordsTheBase_WhenToleratingACacheFailure()
    {
        var cache = NewCache();
        await using var host = new IssuerApiHost(services => { services.RemoveAll<IDistributedCache>(); services.AddSingleton<IDistributedCache>(cache); });
        host.Kit.InitializeLegacy();
        using var scope = host.Factory.Services.CreateScope();
        var publisher = scope.ServiceProvider.GetRequiredService<CrlPublisher>();
        var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
        cache.Failure = RedisDown;

        var published = await publisher.PublishFullCrlAsync(issuer, tolerateCacheFailure: true, Ct);

        Assert.NotEmpty(published.Bytes);
        var (baseNumber, _) = await scope.ServiceProvider.GetRequiredService<IssuerCrlState>().GetBaseAsync(issuer.Issuer, Ct);
        Assert.Equal(published.CrlNumber, baseNumber);
    }

    // ---- eviction retry ---------------------------------------------------------------------------------

    private sealed class RecordingQueue : IBackgroundJobQueue
    {
        public List<(string JobType, string? Key, string? PayloadJson)> Enqueued { get; } = [];

        public Task<BackgroundJob?> EnqueueAsync(string jobType, string? concurrencyKey, string requestedBy, string? reason,
            string? payloadJson = null, CancellationToken cancellationToken = default)
        {
            Enqueued.Add((jobType, concurrencyKey, payloadJson));
            return Task.FromResult<BackgroundJob?>(new BackgroundJob { JobType = jobType, ConcurrencyKey = concurrencyKey });
        }

        public Task<BackgroundJob?> ClaimNextAsync(IReadOnlyCollection<string> handledJobTypes, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task CompleteAsync(BackgroundJob job, string? result, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task ScheduleRetryAsync(BackgroundJob job, string error, DateTime nextAttemptAfterUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task FailAsync(BackgroundJob job, string error, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> RecoverStuckAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> RecoverStaleAsync(DateTime claimedBeforeUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> DeleteFinishedBeforeAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private sealed class CountingSignal : IBackgroundJobSignal
    {
        public int Signals { get; private set; }
        public bool TrySignal() { Signals++; return true; }
        public ValueTask<bool> WaitToReadAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public void Drain() { }
    }

    [Fact]
    public async Task Eviction_ReturnsFalse_WhenTheCacheIsDown_AndStillDropsWhatItCan()
    {
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        var cache = NewCache();
        await cache.SetAsync(CrlCache.Key, [1], Ct);
        cache.Failure = RedisDown;

        var evicted = await CertificateRequestQueueConsumer.EvictCrlAsync(cache, registry,
            new CertificateRequest { CommonName = "r" }, Ct);

        Assert.False(evicted);
    }

    [Fact]
    public async Task FailedEviction_QueuesACrlRefreshJob_ForThatIssuer()
    {
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        var cache = NewCache();
        cache.Failure = RedisDown;
        var queue = new RecordingQueue();
        var signal = new CountingSignal();

        await CertificateRequestQueueConsumer.EvictCrlOrQueueRefreshAsync(cache, registry, Services(queue, signal),
            new CertificateRequest { CommonName = "r" }, NullLogger.Instance, Ct);

        var job = Assert.Single(queue.Enqueued);
        Assert.Equal(WellKnownJobTypes.CrlRefresh, job.JobType);
        Assert.Equal(CrlRefreshJobHandler.ConcurrencyKey, job.Key); // the legacy issuer's key
        Assert.Equal(1, signal.Signals);
    }

    [Fact]
    public async Task SuccessfulEviction_QueuesNothing()
    {
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        var queue = new RecordingQueue();
        var signal = new CountingSignal();

        await CertificateRequestQueueConsumer.EvictCrlOrQueueRefreshAsync(NewCache(), registry, Services(queue, signal),
            new CertificateRequest { CommonName = "r" }, NullLogger.Instance, Ct);

        Assert.Empty(queue.Enqueued);
        Assert.Equal(0, signal.Signals);
    }

    [Fact]
    public async Task SuccessfulEviction_NeedsNeitherTheQueueNorTheSignal()
    {
        // A host without the job queue (as in the older eviction tests) must still evict.
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        var cache = NewCache();
        await cache.SetAsync(CrlCache.Key, [1], Ct);

        await CertificateRequestQueueConsumer.EvictCrlOrQueueRefreshAsync(cache, registry, new ServiceCollection().BuildServiceProvider(),
            new CertificateRequest { CommonName = "r" }, NullLogger.Instance, Ct);

        Assert.Null(await cache.GetAsync(CrlCache.Key, Ct));
    }

    private static IServiceProvider Services(IBackgroundJobQueue queue, IBackgroundJobSignal signal) =>
        new ServiceCollection().AddSingleton(queue).AddSingleton(signal).BuildServiceProvider();

    // ---- client timeouts --------------------------------------------------------------------------------

    [Fact]
    public void RedisClient_GivesUpQuickly_AndKeepsRetryingInTheBackground()
    {
        var options = new ConfigurationOptions();

        QertumRedis.ApplyResilience(options);

        Assert.False(options.AbortOnConnectFail);
        Assert.True(options.ConnectTimeout <= 2000, $"ConnectTimeout {options.ConnectTimeout}");
        Assert.True(options.SyncTimeout <= 2000, $"SyncTimeout {options.SyncTimeout}");
        Assert.True(options.AsyncTimeout <= 2000, $"AsyncTimeout {options.AsyncTimeout}");
        // A request makes several cache calls; queueing each for a second while disconnected added up to ~8 s.
        Assert.False(options.BacklogPolicy.QueueWhileDisconnected);
    }
}
