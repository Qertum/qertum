using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Time.Testing;
using Qertum.IdentityService.Services;

namespace Qertum.Tests.Identity;

public sealed class PasswordAttemptLimiterTests
{
    [Fact]
    public async Task ConcurrentReservationsAllowOnlyFiveAttempts()
    {
        var ct = TestContext.Current.CancellationToken;
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, TimeProvider.System);

        var attempts = await Task.WhenAll(Enumerable.Range(0, 32)
            .Select(_ => limiter.ReserveAsync(PasswordAttemptPurpose.StepUp, "user-1", ct)));

        Assert.Equal([1, 2, 3, 4, 5], attempts.Where(number => number > 0).Order());
        Assert.Equal(27, attempts.Count(number => number == 0));
    }

    [Fact]
    public async Task LoginWindowStartsAtFirstAttemptAndSuccessClearsIt()
    {
        var ct = TestContext.Current.CancellationToken;
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 24, 9, 0, 0, TimeSpan.Zero));
        var limiter = new PasswordAttemptLimiter(cache, clock);

        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.Login, "Alice", ct));
        clock.Advance(TimeSpan.FromMinutes(14));
        Assert.Equal(2, await limiter.ReserveAsync(PasswordAttemptPurpose.Login, "ALICE", ct));
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.Login, "alice", ct));
        await limiter.ClearAsync(PasswordAttemptPurpose.Login, "alice", ct);
        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.Login, "alice", ct));
    }

    [Fact]
    public async Task StepUpWindowSlidesAndPurposesHaveSeparateBudgets()
    {
        var ct = TestContext.Current.CancellationToken;
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 24, 9, 0, 0, TimeSpan.Zero));
        var limiter = new PasswordAttemptLimiter(cache, clock);

        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.StepUp, "user-1", ct));
        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.Equal(2, await limiter.ReserveAsync(PasswordAttemptPurpose.StepUp, "user-1", ct));
        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.Equal(3, await limiter.ReserveAsync(PasswordAttemptPurpose.StepUp, "user-1", ct));
        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.ChangePassword, "user-1", ct));
        clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(1, await limiter.ReserveAsync(PasswordAttemptPurpose.StepUp, "user-1", ct));
    }
}
