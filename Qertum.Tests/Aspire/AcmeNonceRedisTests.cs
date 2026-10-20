using Aspire.Hosting.Testing;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Qertum.Services.Acme;
using StackExchange.Redis;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class AcmeNonceRedisTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-ACME-NONCE-001")]
    public async Task TwoInstancesConsumeSharedNonceOnlyOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        var connectionString = await fixture.App.GetConnectionStringAsync("cache", ct);
        Assert.False(string.IsNullOrWhiteSpace(connectionString));
        await using var redis = await ConnectionMultiplexer.ConnectAsync(connectionString);
        var fallback = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var first = new AcmeNonceService(fallback, redis);
        var second = new AcmeNonceService(fallback, redis);
        var nonce = first.GenerateNonce();

        var attempts = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(index => (index % 2 == 0 ? first : second).ConsumeAsync(nonce, ct)));

        Assert.Single(attempts, accepted => accepted);
        Assert.False(await second.ConsumeAsync(nonce, ct));
    }
}
