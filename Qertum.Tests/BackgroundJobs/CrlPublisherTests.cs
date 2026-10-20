using Microsoft.Extensions.Caching.Distributed;
using Qertum.Services;

namespace Qertum.Tests.BackgroundJobs;

public sealed class CrlPublisherTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Publish_CachesTheCrl_RecordsTheBase_AndEvictsTheCachedDelta()
    {
        await using var host = BackgroundJobTestHost.Create();
        var cache = host.Services.GetRequiredService<IDistributedCache>();
        await cache.SetAsync(CrlCache.Key, [9, 9, 9], Ct);
        await cache.SetAsync(CrlCache.DeltaKey, [8, 8, 8], Ct);

        await using var scope = host.Services.CreateAsyncScope();
        var published = await scope.ServiceProvider.GetRequiredService<CrlPublisher>().PublishFullCrlAsync(Ct);

        Assert.Equal(published.Bytes, await cache.GetAsync(CrlCache.Key, Ct));
        Assert.Null(await cache.GetAsync(CrlCache.DeltaKey, Ct));
        var settings = await host.SettingsAsync();
        Assert.Equal(published.CrlNumber, settings!.BaseCrlNumber);
        Assert.Equal(host.Clock.GetUtcNow().UtcDateTime, settings.BaseCrlThisUpdateUtc);
        Assert.Equal(host.Clock.GetUtcNow().UtcDateTime, published.ThisUpdateUtc);
    }

    [Fact]
    public async Task Publish_ClaimsANewNumberEachTime()
    {
        await using var host = BackgroundJobTestHost.Create();

        await using var scope = host.Services.CreateAsyncScope();
        var publisher = scope.ServiceProvider.GetRequiredService<CrlPublisher>();
        var first = await publisher.PublishFullCrlAsync(Ct);
        var second = await publisher.PublishFullCrlAsync(Ct);

        Assert.True(second.CrlNumber > first.CrlNumber);
    }

    [Theory]
    [InlineData(0, 24)]
    [InlineData(-5, 24)]
    [InlineData(1, 1)]
    [InlineData(48, 48)]
    public void EffectiveValidityHours_TreatsNonPositiveAs24(int configured, int expected)
        => Assert.Equal(expected, CrlPublisher.EffectiveValidityHours(configured));
}
