using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Auth;

/// <summary>Builds the roles overview and the caller's access summary.</summary>
public interface IRoleAccessService
{
    /// <summary>Catalog, grants per role, and drift flags from observed roles.</summary>
    Task<RolePermissionsOverviewResponse> GetOverviewAsync(CancellationToken cancellationToken = default);

    /// <summary>Access for a caller whose roles the endpoint has already mapped.</summary>
    Task<MyAccessResponse> GetMyAccessAsync(IReadOnlyCollection<string> roles, bool isAdmin, CancellationToken cancellationToken = default);
}

/// <summary>
/// Default <see cref="IRoleAccessService"/>. Takes roles and admin status as arguments rather than
/// injecting <see cref="IIdentityClaimsMapper"/>, which only hosts with JWT authentication register.
/// </summary>
public sealed class RoleAccessService(
    CertificateRequestDbContext dbContext,
    IRolePermissionService rolePermissions,
    TimeProvider timeProvider) : IRoleAccessService
{
    /// <inheritdoc />
    public async Task<RolePermissionsOverviewResponse> GetOverviewAsync(CancellationToken cancellationToken = default)
    {
        var grants = await rolePermissions.GetAllRolePermissionsAsync(cancellationToken);
        var observed = await dbContext.ObservedRoles.AsNoTracking().ToListAsync(cancellationToken);
        var observedByName = observed.ToDictionary(o => o.Role, StringComparer.OrdinalIgnoreCase);
        var staleBefore = timeProvider.GetUtcNow().UtcDateTime.AddDays(-ObservedRoleThresholds.StaleAfterDays);

        var roles = grants
            .Where(g => !IsAdmin(g.Key))
            .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                observedByName.TryGetValue(g.Key, out var seen);
                return new RoleGrantSummary
                {
                    Name = g.Key,
                    Permissions = g.Value,
                    FirstSeenUtc = seen is null ? null : Utc(seen.FirstSeenUtc),
                    LastSeenUtc = seen is null ? null : Utc(seen.LastSeenUtc),
                    NeverSeen = seen is null,
                    NotSeenRecently = seen is not null && seen.LastSeenUtc < staleBefore
                };
            })
            .ToList();

        var withoutGrants = observed
            .Where(o => !IsAdmin(o.Role) && !grants.ContainsKey(o.Role))
            .OrderBy(o => o.Role, StringComparer.OrdinalIgnoreCase)
            .Select(o => new ObservedRoleSummary { Name = o.Role, FirstSeenUtc = Utc(o.FirstSeenUtc), LastSeenUtc = Utc(o.LastSeenUtc) })
            .ToList();

        return new RolePermissionsOverviewResponse
        {
            Permissions = AppPermissions.All.Select(p => new PermissionInfo { Name = p, Description = AppPermissions.Descriptions[p] }).ToList(),
            Roles = roles,
            ObservedWithoutPermissions = withoutGrants,
            TrackingStartedUtc = observed.Count == 0 ? null : Utc(observed.Min(o => o.FirstSeenUtc)),
            StaleAfterDays = ObservedRoleThresholds.StaleAfterDays
        };
    }

    /// <inheritdoc />
    public async Task<MyAccessResponse> GetMyAccessAsync(IReadOnlyCollection<string> roles, bool isAdmin, CancellationToken cancellationToken = default)
    {
        var effective = isAdmin
            ? AppPermissions.All
            : await rolePermissions.GetEffectivePermissionsAsync(roles, cancellationToken);

        return new MyAccessResponse
        {
            Roles = roles.ToList(),
            IsAdmin = isAdmin,
            Permissions = AppPermissions.All.Select(p => new MyAccessPermission
            {
                Name = p,
                Description = AppPermissions.Descriptions[p],
                Granted = effective.Contains(p)
            }).ToList()
        };
    }

    private static bool IsAdmin(string role) => string.Equals(role, AppRoles.Admin, StringComparison.OrdinalIgnoreCase);

    // SQLite returns DateTimeKind.Unspecified; the values are written as UTC.
    private static DateTime Utc(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
