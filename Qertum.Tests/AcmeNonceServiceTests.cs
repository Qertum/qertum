using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Distributed;
using Qertum.Services.Acme;

namespace Qertum.Tests;

public sealed class AcmeNonceServiceTests
{
    [Fact]
    public async Task ConcurrentRequestsConsumeOneNonceOnlyOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var service = new AcmeNonceService(new DelayedMemoryCache());
        var nonce = service.GenerateNonce();

        var attempts = await Task.WhenAll(
            service.ConsumeAsync(nonce, ct), service.ConsumeAsync(nonce, ct));

        Assert.Single(attempts, accepted => accepted);
        Assert.False(await service.ConsumeAsync(nonce, ct));
    }

    private sealed class DelayedMemoryCache : IDistributedCache
    {
        private readonly ConcurrentDictionary<string, byte[]> _entries = new();

        public byte[]? Get(string key) => _entries.GetValueOrDefault(key);

        public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
        {
            var value = Get(key);
            await Task.Delay(50, token);
            return value;
        }

        public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
            => _entries[key] = value;

        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options,
            CancellationToken token = default)
        {
            Set(key, value, options);
            return Task.CompletedTask;
        }

        public void Refresh(string key) { }

        public Task RefreshAsync(string key, CancellationToken token = default)
            => Task.CompletedTask;

        public void Remove(string key) => _entries.TryRemove(key, out _);

        public Task RemoveAsync(string key, CancellationToken token = default)
        {
            Remove(key);
            return Task.CompletedTask;
        }
    }
}
