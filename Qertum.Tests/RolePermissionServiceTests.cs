using Qertum.Services;
using Qertum.Tests.Policies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Tests;

public sealed class RolePermissionServiceTests
{
    [Fact]
    public async Task GetEffectivePermissionsAsync_ReturnsUnionOfAllRolePermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        await scope.Service.SetPermissionsForRoleAsync("viewer",
            [AppPermissions.CertificatesView], "tester", ct);
        await scope.Service.SetPermissionsForRoleAsync("creator",
            [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate], "tester", ct);

        var effective = await scope.Service.GetEffectivePermissionsAsync(["viewer", "creator"], ct);

        Assert.Contains(AppPermissions.CertificatesView, effective);
        Assert.Contains(AppPermissions.CertificatesCreate, effective);
        Assert.Equal(2, effective.Count);
    }

    [Fact]
    public async Task SetPermissionsForRoleAsync_ReplacesExistingPermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        await scope.Service.SetPermissionsForRoleAsync("editor",
            [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate], "tester", ct);

        await scope.Service.SetPermissionsForRoleAsync("editor",
            [AppPermissions.CertificatesManage], "tester", ct);

        var permissions = await scope.Service.GetPermissionsForRoleAsync("editor", ct);

        Assert.Single(permissions);
        Assert.Contains(AppPermissions.CertificatesManage, permissions);
    }

    [Fact]
    public async Task GetEffectivePermissionsAsync_RoleWithNoPermissions_ReturnsEmpty()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var effective = await scope.Service.GetEffectivePermissionsAsync(["unknown-role"], ct);

        Assert.Empty(effective);
    }

    [Fact]
    public async Task GetEffectivePermissionsAsync_AdminRole_ReturnsAllPermissions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();

        var effective = await scope.Service.GetEffectivePermissionsAsync(["admin"], ct);

        foreach (var permission in AppPermissions.All)
            Assert.Contains(permission, effective);
        Assert.Equal(AppPermissions.All.Count, effective.Count);
    }

    [Fact]
    public async Task Set_ComputesGrantedAndRevoked_AuditsAndRaisesWebhook()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await scope.Service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView, AppPermissions.SettingsEdit], "tester", ct);
        scope.Audit.Entries.Clear();
        scope.Webhooks.Events.Clear();

        var change = await scope.Service.SetPermissionsForRoleAsync("ops",
            [AppPermissions.CertificatesView, AppPermissions.PoliciesPublish, AppPermissions.CertificatesManage], "alice", ct);

        Assert.Equal(["certificates.manage", "policies.publish"], change.Granted);
        Assert.Equal(["settings.edit"], change.Revoked);
        var entry = Assert.Single(scope.Audit.Entries);
        Assert.Equal(("RolePermissionsUpdated", "alice", "ops"), (entry.Action, entry.PerformedBy, entry.ResourceName));
        Assert.Equal("+certificates.manage +policies.publish -settings.edit", entry.Detail);
        var evt = Assert.Single(scope.Webhooks.Events);
        Assert.Equal(WellKnownWebhookEvents.RolePermissionsUpdated, evt.EventType);
        Assert.Equal("ops", evt.ResourceName);
        Assert.Equal("ops", evt.Fields!["role"]);
        Assert.Equal("certificates.manage,policies.publish", evt.Fields["grantedPermissions"]);
        Assert.Equal("settings.edit", evt.Fields["revokedPermissions"]);
    }

    [Fact]
    public async Task Set_NoChange_WritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await scope.Service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);
        scope.Audit.Entries.Clear();
        scope.Webhooks.Events.Clear();

        var change = await scope.Service.SetPermissionsForRoleAsync("OPS",
            [AppPermissions.CertificatesView, AppPermissions.CertificatesView], "tester", ct);

        Assert.True(change.IsNoOp);
        Assert.Empty(scope.Audit.Entries);
        Assert.Empty(scope.Webhooks.Events);
    }

    [Fact]
    public async Task Set_DifferentCase_KeepsStoredSpelling()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await scope.Service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);

        var change = await scope.Service.SetPermissionsForRoleAsync("OPS",
            [AppPermissions.CertificatesView, AppPermissions.SettingsEdit], "tester", ct);

        Assert.Equal("ops", change.Role);
        var all = await scope.Service.GetAllRolePermissionsAsync(ct);
        var (key, perms) = Assert.Single(all);
        Assert.Equal("ops", key);
        Assert.Equal([AppPermissions.CertificatesView, AppPermissions.SettingsEdit], perms);
        Assert.True(all.ContainsKey("Ops"));
    }

    [Fact]
    public async Task Effective_TokenRoleCaseDiffers_StillGranted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await scope.Service.SetPermissionsForRoleAsync("operators", [AppPermissions.CertificatesManage], "tester", ct);

        Assert.Equal([AppPermissions.CertificatesManage], await scope.Service.GetEffectivePermissionsAsync(["Operators"], ct));
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("ADMIN")]
    [InlineData(" ops")]
    public async Task Set_RefusedRole_Throws(string role)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            scope.Service.SetPermissionsForRoleAsync(role, [AppPermissions.CertificatesView], "tester", ct));
    }

    [Fact]
    public async Task Set_UnknownPermission_ThrowsAndWritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await CreateTestScopeAsync();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            scope.Service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView, "not.real"], "tester", ct));
        Assert.Empty(await scope.Service.GetPermissionsForRoleAsync("ops", ct));
    }

    private static async Task<TestScope> CreateTestScopeAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection)
            .Options;

        var dbContext = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        await dbContext.Database.EnsureCreatedAsync(ct);

        var cache = new Microsoft.Extensions.Caching.Memory.MemoryCache(
            new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions());
        var audit = new RecordingPolicyAuditLog();
        var webhooks = new RoleRecordingWebhookService();
        return new TestScope(connection, dbContext,
            new RolePermissionService(dbContext, cache, audit, webhooks,
                new Microsoft.Extensions.Caching.Distributed.MemoryDistributedCache(
                    Microsoft.Extensions.Options.Options.Create(
                        new Microsoft.Extensions.Caching.Memory.MemoryDistributedCacheOptions())),
                Microsoft.Extensions.Logging.Abstractions.NullLogger<RolePermissionService>.Instance),
            audit, webhooks);
    }

    private sealed class TestScope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        RolePermissionService service,
        RecordingPolicyAuditLog audit,
        RoleRecordingWebhookService webhooks) : IAsyncDisposable
    {
        public RolePermissionService Service { get; } = service;

        public RecordingPolicyAuditLog Audit { get; } = audit;

        public RoleRecordingWebhookService Webhooks { get; } = webhooks;

        public async ValueTask DisposeAsync()
        {
            await dbContext.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}

internal sealed class RoleRecordingWebhookService : IWebhookService
{
    public List<WebhookEvent> Events { get; } = [];
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        Events.Add(webhookEvent);
        return Task.CompletedTask;
    }
}
