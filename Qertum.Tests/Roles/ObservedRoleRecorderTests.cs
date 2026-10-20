using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Auth;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Roles;

public sealed class ObservedRoleRecorderTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 14, 10, 0, 0, TimeSpan.Zero);

    private static ObservedRoleRecorder Recorder(PolicyTestDb scope, IMemoryCache cache, TimeProvider time) =>
        new(scope.Db, cache, time, NullLogger<ObservedRoleRecorder>.Instance);

    private static async Task<ObservedRole?> RowAsync(PolicyTestDb scope, string role, CancellationToken ct) =>
        await scope.Db.ObservedRoles.AsNoTracking().SingleOrDefaultAsync(r => r.Role == role, ct);

    [Fact]
    public async Task FirstSighting_InsertsRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var time = new FakeTimeProvider(Start);

        await Recorder(scope, new MemoryCache(new MemoryCacheOptions()), time).RecordAsync(["auditors"], ct);

        var row = await RowAsync(scope, "auditors", ct);
        Assert.NotNull(row);
        Assert.Equal(Start.UtcDateTime, row.FirstSeenUtc);
        Assert.Equal(Start.UtcDateTime, row.LastSeenUtc);
    }

    [Fact]
    public async Task WithinThrottle_DoesNotWrite_AfterThrottle_UpdatesLastSeenOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var time = new FakeTimeProvider(Start);
        var cache = new MemoryCache(new MemoryCacheOptions());

        await Recorder(scope, cache, time).RecordAsync(["auditors"], ct);
        time.Advance(TimeSpan.FromMinutes(30));
        await Recorder(scope, cache, time).RecordAsync(["AUDITORS"], ct);
        Assert.Equal(Start.UtcDateTime, (await RowAsync(scope, "auditors", ct))!.LastSeenUtc);

        time.Advance(TimeSpan.FromMinutes(31));
        await Recorder(scope, cache, time).RecordAsync(["Auditors"], ct);

        var row = (await RowAsync(scope, "auditors", ct))!;
        Assert.Equal("auditors", row.Role);
        Assert.Equal(Start.UtcDateTime, row.FirstSeenUtc);
        Assert.Equal(Start.AddMinutes(61).UtcDateTime, row.LastSeenUtc);
    }

    [Fact]
    public async Task InvalidNames_AreSkipped_AndAtMost50Recorded()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var roles = new List<string> { " padded", "a/b" };
        roles.AddRange(Enumerable.Range(0, 60).Select(i => $"role-{i}"));

        await Recorder(scope, new MemoryCache(new MemoryCacheOptions()), new FakeTimeProvider(Start)).RecordAsync(roles, ct);

        Assert.Equal(ObservedRoleRecorder.MaxRolesPerRequest, await scope.Db.ObservedRoles.CountAsync(ct));
        Assert.False(await scope.Db.ObservedRoles.AnyAsync(r => r.Role == " padded" || r.Role == "a/b", ct));
    }

    [Fact]
    public async Task DatabaseFailure_IsSwallowed()
    {
        var ct = TestContext.Current.CancellationToken;
        var scope = await PolicyTestDb.CreateAsync(ct);
        var recorder = Recorder(scope, new MemoryCache(new MemoryCacheOptions()), new FakeTimeProvider(Start));
        await scope.DisposeAsync();

        await recorder.RecordAsync(["auditors"], ct);
    }
}
