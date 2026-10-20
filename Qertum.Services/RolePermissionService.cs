using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Qertum.Services;

public sealed class RolePermissionService(
    CertificateRequestDbContext dbContext,
    IMemoryCache cache,
    IAuditLogService auditLog,
    IWebhookService webhookService,
    IDistributedCache sharedCache,
    ILogger<RolePermissionService> logger) : IRolePermissionService
{
    public async Task<IReadOnlyList<string>> GetPermissionsForRoleAsync(string role, CancellationToken cancellationToken = default)
    {
        var permissions = await dbContext.RolePermissions
            .Where(rp => rp.Role == role)
            .Select(rp => rp.Permission)
            .ToListAsync(cancellationToken);

        return permissions;
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<string>>> GetAllRolePermissionsAsync(CancellationToken cancellationToken = default)
    {
        var all = await dbContext.RolePermissions.AsNoTracking()
            .OrderBy(rp => rp.Id)
            .ToListAsync(cancellationToken);

        // Rows are ordered by Id, so First() is the lowest-Id spelling: the role's display name.
        return all
            .GroupBy(rp => rp.Role, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.First().Role,
                IReadOnlyList<string> (g) => OrderLikeCatalog(g.Select(rp => rp.Permission)),
                StringComparer.OrdinalIgnoreCase);
    }

    public async Task<RolePermissionChange> SetPermissionsForRoleAsync(
        string role, IEnumerable<string> permissions, string performedBy, CancellationToken cancellationToken = default)
    {
        if (!RoleNameRules.TryValidate(role, out var roleError))
            throw new ArgumentException(roleError, nameof(role));
        if (string.Equals(role, AppRoles.Admin, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Admin role permissions cannot be modified.", nameof(role));

        var requested = permissions.Distinct(StringComparer.Ordinal).ToList();
        var unknown = requested.Where(p => !AppPermissions.All.Contains(p)).ToList();
        if (unknown.Count > 0)
            throw new ArgumentException($"Unknown permissions: {string.Join(", ", unknown)}", nameof(permissions));

        // NOCASE column: this matches every spelling of the role.
        var existing = await dbContext.RolePermissions
            .Where(rp => rp.Role == role)
            .OrderBy(rp => rp.Id)
            .ToListAsync(cancellationToken);

        var storedRole = existing.Count > 0 ? existing[0].Role : role;
        var granted = requested.Where(p => existing.All(e => e.Permission != p)).Order(StringComparer.Ordinal).ToList();
        var revokedRows = existing.Where(e => !requested.Contains(e.Permission)).ToList();
        var revoked = revokedRows.Select(e => e.Permission).Order(StringComparer.Ordinal).ToList();
        var change = new RolePermissionChange(storedRole, granted, revoked);

        if (change.IsNoOp)
            return change;

        dbContext.RolePermissions.RemoveRange(revokedRows);
        dbContext.RolePermissions.AddRange(granted.Select(p => new RolePermission { Role = storedRole, Permission = p }));
        await dbContext.SaveChangesAsync(cancellationToken);

        InvalidateCache();
        await BumpVersionAsync(cancellationToken);

        var detail = string.Join(' ', granted.Select(p => "+" + p).Concat(revoked.Select(p => "-" + p)));
        await auditLog.LogAsync(WellKnownWebhookEvents.RolePermissionsUpdated, performedBy,
            resourceName: storedRole, detail: detail, cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.RolePermissionsUpdated,
            ResourceName: storedRole,
            Detail: detail,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["role"] = storedRole,
                ["grantedPermissions"] = string.Join(',', granted),
                ["revokedPermissions"] = string.Join(',', revoked)
            }), cancellationToken);

        return change;
    }

    public async Task<RoleRenameOutcome> RenameRoleAsync(
        string role, string newRole, string performedBy, CancellationToken cancellationToken = default)
    {
        foreach (var (value, parameter) in new[] { (role, nameof(role)), (newRole, nameof(newRole)) })
        {
            if (!RoleNameRules.TryValidate(value, out var error))
                throw new ArgumentException(error, parameter);
            if (string.Equals(value, AppRoles.Admin, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The admin role is built in and cannot be renamed.", parameter);
        }

        // NOCASE: these comparisons match every spelling of the names.
        var rows = await dbContext.RolePermissions.Where(rp => rp.Role == role).OrderBy(rp => rp.Id).ToListAsync(cancellationToken);
        if (rows.Count == 0)
            return RoleRenameOutcome.SourceNotFound;

        var previousRole = rows[0].Role;
        var renamingCaseOnly = string.Equals(previousRole, newRole, StringComparison.OrdinalIgnoreCase);
        if (!renamingCaseOnly && await dbContext.RolePermissions.AnyAsync(rp => rp.Role == newRole, cancellationToken))
            return RoleRenameOutcome.TargetExists;

        foreach (var row in rows)
            row.Role = newRole;
        await dbContext.SaveChangesAsync(cancellationToken);

        InvalidateCache();
        await BumpVersionAsync(cancellationToken);

        var detail = $"{previousRole} -> {newRole}";
        await auditLog.LogAsync(WellKnownWebhookEvents.RolePermissionsRenamed, performedBy,
            resourceName: newRole, detail: detail, cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.RolePermissionsRenamed,
            ResourceName: newRole,
            Detail: detail,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["role"] = newRole,
                ["previousRole"] = previousRole
            }), cancellationToken);

        return RoleRenameOutcome.Renamed;
    }

    private static IReadOnlyList<string> OrderLikeCatalog(IEnumerable<string> permissions)
    {
        var set = permissions.ToHashSet(StringComparer.Ordinal);
        return AppPermissions.All.Where(set.Contains).ToList();
    }

    private void InvalidateCache()
    {
        // Cancel the shared invalidation token so all cache entries expire immediately.
        if (cache.TryGetValue(PermissionsCacheTag, out CancellationTokenSource? cts) && cts is not null)
        {
            cache.Remove(PermissionsCacheTag);
            cts.Cancel();
            cts.Dispose();
        }
    }

    private const string PermissionsCacheTag = "role-permissions";

    /// <summary>
    /// Shared stamp bumped by every save that wrote rows. It is folded into each instance's
    /// memory-cache key, so an entry written before another instance's save is simply unreachable —
    /// no cross-instance invalidation message has to be delivered.
    /// </summary>
    public const string VersionCacheKey = "role-permissions:version";

    private string _lastKnownVersion = "0";

    private async Task<string> GetVersionAsync(CancellationToken cancellationToken)
    {
        try
        {
            var stamp = await sharedCache.GetStringAsync(VersionCacheKey, cancellationToken);
            if (!string.IsNullOrEmpty(stamp))
                _lastKnownVersion = stamp;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // An unreachable shared cache degrades to per-instance staleness, never to a failed
            // authorization: the last stamp we saw keeps the existing entries usable.
            logger.LogWarning(ex, "Shared permission stamp unavailable; using the last known value.");
        }

        return _lastKnownVersion;
    }

    private async Task BumpVersionAsync(CancellationToken cancellationToken)
    {
        var stamp = Guid.NewGuid().ToString("N");
        try
        {
            await sharedCache.SetStringAsync(VersionCacheKey, stamp, cancellationToken);
            _lastKnownVersion = stamp;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not publish the permission stamp; other instances refresh on their own expiry.");
        }
    }
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    public async Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(IEnumerable<string> roles, CancellationToken cancellationToken = default)
    {
        var roleList = roles.OrderBy(r => r, StringComparer.OrdinalIgnoreCase).ToList();

        // Admin always gets all permissions; no DB hit needed.
        if (roleList.Contains(AppRoles.Admin, StringComparer.OrdinalIgnoreCase))
            return AppPermissions.All;

        var version = await GetVersionAsync(cancellationToken);
        var cacheKey = $"{PermissionsCacheTag}:{version}:{string.Join(",", roleList.Select(r => r.ToLowerInvariant()).Order(StringComparer.Ordinal))}";
        if (cache.TryGetValue(cacheKey, out IReadOnlyList<string>? cached) && cached is not null)
            return cached;

        var permissions = await dbContext.RolePermissions
            .Where(rp => roleList.Contains(rp.Role))
            .Select(rp => rp.Permission)
            .Distinct()
            .ToListAsync(cancellationToken);

        cache.Set<IReadOnlyList<string>>(cacheKey, permissions,
            new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = CacheTtl }
                .AddExpirationToken(new Microsoft.Extensions.Primitives.CancellationChangeToken(
                    GetOrCreateCacheInvalidationToken())));

        return permissions;
    }

    private CancellationToken GetOrCreateCacheInvalidationToken()
    {
        if (cache.TryGetValue(PermissionsCacheTag, out CancellationTokenSource? cts) && cts is not null)
            return cts.Token;

        cts = new CancellationTokenSource();
        cache.Set(PermissionsCacheTag, cts);
        return cts.Token;
    }
}
