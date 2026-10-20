using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Roles;

public sealed class RoleRenameServiceTests
{
    private static (RolePermissionService Service, RoleRecordingWebhookService Webhooks) Create(PolicyTestDb scope)
    {
        var webhooks = new RoleRecordingWebhookService();
        var service = new RolePermissionService(
            scope.Db, new MemoryCache(new MemoryCacheOptions()), scope.Audit, webhooks,
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            NullLogger<RolePermissionService>.Instance);
        return (service, webhooks);
    }

    [Fact]
    public async Task Rename_MovesGrants_AuditsAndRaisesWebhook_AndLeavesObservedRolesAlone()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (service, webhooks) = Create(scope);
        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView, AppPermissions.SettingsEdit], "tester", ct);
        scope.Db.ObservedRoles.Add(new ObservedRole { Role = "ops", FirstSeenUtc = DateTime.UtcNow, LastSeenUtc = DateTime.UtcNow });
        await scope.Db.SaveChangesAsync(ct);
        scope.Audit.Entries.Clear();
        webhooks.Events.Clear();

        var outcome = await service.RenameRoleAsync("ops", "platform", "alice", ct);

        Assert.Equal(RoleRenameOutcome.Renamed, outcome);
        Assert.Equal([AppPermissions.CertificatesView, AppPermissions.SettingsEdit],
            await service.GetPermissionsForRoleAsync("platform", ct));
        Assert.Empty(await service.GetPermissionsForRoleAsync("ops", ct));
        Assert.Equal(["ops"], await scope.Db.ObservedRoles.Select(r => r.Role).ToListAsync(ct));

        var entry = Assert.Single(scope.Audit.Entries);
        Assert.Equal(("RolePermissionsRenamed", "alice", "platform"), (entry.Action, entry.PerformedBy, entry.ResourceName));
        Assert.Contains("ops", entry.Detail);
        var evt = Assert.Single(webhooks.Events);
        Assert.Equal(WellKnownWebhookEvents.RolePermissionsRenamed, evt.EventType);
        Assert.Equal("platform", evt.Fields!["role"]);
        Assert.Equal("ops", evt.Fields["previousRole"]);
    }

    [Fact]
    public async Task Rename_UnknownSource_IsNotFound_AndOccupiedTargetIsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (service, _) = Create(scope);
        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);
        await service.SetPermissionsForRoleAsync("platform", [AppPermissions.SettingsEdit], "tester", ct);

        Assert.Equal(RoleRenameOutcome.SourceNotFound, await service.RenameRoleAsync("nobody", "somebody", "alice", ct));
        Assert.Equal(RoleRenameOutcome.TargetExists, await service.RenameRoleAsync("ops", "PLATFORM", "alice", ct));
        Assert.Equal([AppPermissions.CertificatesView], await service.GetPermissionsForRoleAsync("ops", ct));
    }

    [Fact]
    public async Task Rename_CaseOnlyChange_KeepsGrantsAndRewritesSpelling()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (service, _) = Create(scope);
        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);

        Assert.Equal(RoleRenameOutcome.Renamed, await service.RenameRoleAsync("ops", "Ops", "alice", ct));

        var all = await service.GetAllRolePermissionsAsync(ct);
        Assert.Equal("Ops", Assert.Single(all).Key);
    }

    [Theory]
    [InlineData("admin", "ops")]
    [InlineData("ops", "admin")]
    [InlineData("ops", "bad/name")]
    [InlineData("ops", " padded")]
    public async Task Rename_RefusedNames_Throw(string from, string to)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var (service, _) = Create(scope);
        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);

        await Assert.ThrowsAsync<ArgumentException>(() => service.RenameRoleAsync(from, to, "alice", ct));
    }
}
