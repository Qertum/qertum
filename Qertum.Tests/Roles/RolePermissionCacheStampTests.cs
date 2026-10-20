using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Roles;

/// <summary>
/// Two API instances share the database and the distributed cache but have their own memory cache.
/// Without a shared stamp the second instance keeps serving a revoked grant for up to 60 seconds.
/// </summary>
public sealed class RolePermissionCacheStampTests
{
    private sealed class ThrowingDistributedCache : IDistributedCache
    {
        public byte[]? Get(string key) => throw new InvalidOperationException("cache down");
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache down");
        public void Refresh(string key) => throw new InvalidOperationException("cache down");
        public Task RefreshAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache down");
        public void Remove(string key) => throw new InvalidOperationException("cache down");
        public Task RemoveAsync(string key, CancellationToken token = default) => throw new InvalidOperationException("cache down");
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => throw new InvalidOperationException("cache down");
        public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default) => throw new InvalidOperationException("cache down");
    }

    private static RolePermissionService Instance(PolicyTestDb scope, IDistributedCache shared) =>
        new(scope.Db, new MemoryCache(new MemoryCacheOptions()), scope.Audit, new NullPolicyWebhookService(), shared,
            NullLogger<RolePermissionService>.Instance);

    private static IDistributedCache SharedCache() =>
        new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

    [Fact]
    public async Task RevokeOnOneInstance_IsSeenByTheOther()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var shared = SharedCache();
        var writer = Instance(scope, shared);
        var reader = Instance(scope, shared);

        await writer.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesManage], "tester", ct);
        Assert.Equal([AppPermissions.CertificatesManage], await reader.GetEffectivePermissionsAsync(["ops"], ct));

        await writer.SetPermissionsForRoleAsync("ops", [], "tester", ct);

        Assert.Empty(await reader.GetEffectivePermissionsAsync(["ops"], ct));
    }

    [Fact]
    public async Task NoOpSave_DoesNotChangeTheStamp()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var shared = SharedCache();
        var service = Instance(scope, shared);

        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);
        var afterChange = await shared.GetStringAsync(RolePermissionService.VersionCacheKey, ct);

        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);

        Assert.Equal(afterChange, await shared.GetStringAsync(RolePermissionService.VersionCacheKey, ct));
    }

    [Fact]
    public async Task UnavailableCache_StillAnswers()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = Instance(scope, new ThrowingDistributedCache());

        await service.SetPermissionsForRoleAsync("ops", [AppPermissions.CertificatesView], "tester", ct);

        Assert.Equal([AppPermissions.CertificatesView], await service.GetEffectivePermissionsAsync(["ops"], ct));
    }
}
