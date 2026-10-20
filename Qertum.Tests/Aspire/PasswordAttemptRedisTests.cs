using Aspire.Hosting.Testing;
using Microsoft.Extensions.Caching.Memory;
using Qertum.IdentityService.Services;
using StackExchange.Redis;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class PasswordAttemptRedisTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-IDENTITY-THROTTLE-001")]
    public async Task TwoInstancesShareOneAttemptBudget()
    {
        var ct = TestContext.Current.CancellationToken;
        var connectionString = await fixture.App.GetConnectionStringAsync("cache", ct);
        Assert.False(string.IsNullOrWhiteSpace(connectionString));
        await using var firstRedis = await ConnectionMultiplexer.ConnectAsync(connectionString);
        await using var secondRedis = await ConnectionMultiplexer.ConnectAsync(connectionString);
        using var firstCache = new MemoryCache(new MemoryCacheOptions());
        using var secondCache = new MemoryCache(new MemoryCacheOptions());
        var first = new PasswordAttemptLimiter(firstCache, TimeProvider.System, firstRedis);
        var second = new PasswordAttemptLimiter(secondCache, TimeProvider.System, secondRedis);
        var identity = Guid.NewGuid().ToString();

        var attempts = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(index => (index % 2 == 0 ? first : second)
                .ReserveAsync(PasswordAttemptPurpose.Login, identity, ct)));

        Assert.Equal([1, 2, 3, 4, 5], attempts.Where(number => number > 0).Order());
        Assert.Equal(27, attempts.Count(number => number == 0));
        await second.ClearAsync(PasswordAttemptPurpose.Login, identity, ct);
        Assert.Equal(1, await first.ReserveAsync(PasswordAttemptPurpose.Login, identity, ct));
        await first.ClearAsync(PasswordAttemptPurpose.Login, identity, ct);
    }
}
