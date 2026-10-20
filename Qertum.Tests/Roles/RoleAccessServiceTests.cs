using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Auth;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Roles;

public sealed class RoleAccessServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 14, 12, 0, 0, TimeSpan.Zero);

    private static RoleAccessService Service(PolicyTestDb scope, FakeTimeProvider time) =>
        new(scope.Db,
            new RolePermissionService(scope.Db, new MemoryCache(new MemoryCacheOptions()), scope.Audit, new NullPolicyWebhookService(),
                new Microsoft.Extensions.Caching.Distributed.MemoryDistributedCache(
                    Microsoft.Extensions.Options.Options.Create(new MemoryDistributedCacheOptions())),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<RolePermissionService>.Instance),
            time);

    private static async Task SeedAsync(PolicyTestDb scope, CancellationToken ct)
    {
        scope.Db.RolePermissions.AddRange(
            new RolePermission { Role = "fresh", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "stale", Permission = AppPermissions.CertificatesManage },
            new RolePermission { Role = "ghost", Permission = AppPermissions.SettingsEdit });
        scope.Db.ObservedRoles.AddRange(
            new ObservedRole { Role = "FRESH", FirstSeenUtc = Now.AddDays(-40).UtcDateTime, LastSeenUtc = Now.AddHours(-1).UtcDateTime },
            new ObservedRole { Role = "stale", FirstSeenUtc = Now.AddDays(-45).UtcDateTime, LastSeenUtc = Now.AddDays(-31).UtcDateTime },
            new ObservedRole { Role = "auditors", FirstSeenUtc = Now.AddDays(-2).UtcDateTime, LastSeenUtc = Now.AddDays(-1).UtcDateTime },
            new ObservedRole { Role = "admin", FirstSeenUtc = Now.AddDays(-2).UtcDateTime, LastSeenUtc = Now.AddDays(-1).UtcDateTime });
        await scope.Db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Overview_FlagsDrift()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(scope, ct);

        var overview = await Service(scope, new FakeTimeProvider(Now)).GetOverviewAsync(ct);

        Assert.Equal(AppPermissions.All, overview.Permissions.Select(p => p.Name));
        Assert.Equal(["fresh", "ghost", "stale"], overview.Roles.Select(r => r.Name));
        var fresh = overview.Roles[0];
        Assert.False(fresh.NeverSeen);
        Assert.False(fresh.NotSeenRecently);
        var ghost = overview.Roles[1];
        Assert.True(ghost.NeverSeen);
        Assert.Null(ghost.LastSeenUtc);
        var stale = overview.Roles[2];
        Assert.False(stale.NeverSeen);
        Assert.True(stale.NotSeenRecently);
        Assert.Equal(["auditors"], overview.ObservedWithoutPermissions.Select(o => o.Name));
        Assert.Equal(Now.AddDays(-45).UtcDateTime, overview.TrackingStartedUtc);
        Assert.Equal(DateTimeKind.Utc, overview.TrackingStartedUtc!.Value.Kind);
        Assert.Equal(30, overview.StaleAfterDays);
    }

    [Fact]
    public async Task Overview_EmptyTracking_HasNullStart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var overview = await Service(scope, new FakeTimeProvider(Now)).GetOverviewAsync(ct);

        Assert.Null(overview.TrackingStartedUtc);
        Assert.Empty(overview.Roles);
    }

    [Fact]
    public async Task MyAccess_ListsEveryPermissionWithGrantedFlag()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(scope, ct);
        var service = Service(scope, new FakeTimeProvider(Now));

        var mine = await service.GetMyAccessAsync(["Fresh"], isAdmin: false, ct);
        Assert.Equal(["Fresh"], mine.Roles);
        Assert.False(mine.IsAdmin);
        Assert.Equal(AppPermissions.All, mine.Permissions.Select(p => p.Name));
        Assert.Equal([AppPermissions.CertificatesView], mine.Permissions.Where(p => p.Granted).Select(p => p.Name));

        var admin = await service.GetMyAccessAsync(["admin"], isAdmin: true, ct);
        Assert.All(admin.Permissions, p => Assert.True(p.Granted));
    }
}
