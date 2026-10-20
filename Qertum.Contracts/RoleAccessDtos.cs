namespace Qertum.Services;

/// <summary>Result of replacing a role's permissions.</summary>
/// <param name="Role">The role as stored (its first-saved spelling).</param>
/// <param name="Granted">Permissions added by this save, ordinal-sorted.</param>
/// <param name="Revoked">Permissions removed by this save, ordinal-sorted.</param>
public sealed record RolePermissionChange(string Role, IReadOnlyList<string> Granted, IReadOnlyList<string> Revoked)
{
    /// <summary>True when the save changed nothing and so wrote nothing.</summary>
    public bool IsNoOp => Granted.Count == 0 && Revoked.Count == 0;
}

/// <summary>Thresholds for flagging granted roles no token has carried lately.</summary>
public static class ObservedRoleThresholds
{
    /// <summary>A granted role whose last sighting is older than this many days is flagged.</summary>
    public const int StaleAfterDays = 30;
}

/// <summary>A permission and its plain-language description.</summary>
public sealed class PermissionInfo
{
    /// <summary>Permission constant, e.g. <c>certificates.view</c>.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>What the permission allows.</summary>
    public string Description { get; init; } = string.Empty;
}

/// <summary>One role's grants and when a token carrying it was last seen.</summary>
public sealed class RoleGrantSummary
{
    /// <summary>Role name in its stored spelling.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Granted permissions, in catalog order.</summary>
    public IReadOnlyList<string> Permissions { get; init; } = [];

    /// <summary>First sighting in a token (UTC), null if never seen.</summary>
    public DateTime? FirstSeenUtc { get; init; }

    /// <summary>Latest recorded sighting (UTC), null if never seen.</summary>
    public DateTime? LastSeenUtc { get; init; }

    /// <summary>No token carrying this role has reached the API since tracking began.</summary>
    public bool NeverSeen { get; init; }

    /// <summary>Last seen longer ago than <see cref="ObservedRoleThresholds.StaleAfterDays"/>.</summary>
    public bool NotSeenRecently { get; init; }
}

/// <summary>A role seen in tokens that has no grants.</summary>
public sealed class ObservedRoleSummary
{
    /// <summary>Role name as first seen.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>First sighting (UTC).</summary>
    public DateTime FirstSeenUtc { get; init; }

    /// <summary>Latest recorded sighting (UTC).</summary>
    public DateTime LastSeenUtc { get; init; }
}

/// <summary>Everything the roles page needs: catalog, grants and drift.</summary>
public sealed class RolePermissionsOverviewResponse
{
    /// <summary>All permissions in catalog order, with descriptions.</summary>
    public IReadOnlyList<PermissionInfo> Permissions { get; init; } = [];

    /// <summary>Roles with at least one grant, excluding <c>admin</c>, sorted case-insensitively.</summary>
    public IReadOnlyList<RoleGrantSummary> Roles { get; init; } = [];

    /// <summary>Roles seen in tokens that have no grants, excluding <c>admin</c>.</summary>
    public IReadOnlyList<ObservedRoleSummary> ObservedWithoutPermissions { get; init; } = [];

    /// <summary>Earliest recorded sighting (UTC), or null when nothing has been recorded yet.</summary>
    public DateTime? TrackingStartedUtc { get; init; }

    /// <summary>The stale threshold the flags were computed with.</summary>
    public int StaleAfterDays { get; init; }
}

/// <summary>A permission and whether the caller holds it.</summary>
public sealed class MyAccessPermission
{
    /// <summary>Permission constant.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>What the permission allows.</summary>
    public string Description { get; init; } = string.Empty;

    /// <summary>Whether the caller holds it.</summary>
    public bool Granted { get; init; }
}

/// <summary>The caller's access as the API reads it from their token.</summary>
public sealed class MyAccessResponse
{
    /// <summary>Roles the API mapped from the caller's token.</summary>
    public IReadOnlyList<string> Roles { get; init; } = [];

    /// <summary>Whether the caller holds the built-in admin role.</summary>
    public bool IsAdmin { get; init; }

    /// <summary>Every permission, in catalog order, with <see cref="MyAccessPermission.Granted"/>.</summary>
    public IReadOnlyList<MyAccessPermission> Permissions { get; init; } = [];
}

/// <summary>Result of renaming a role's grants.</summary>
public enum RoleRenameOutcome
{
    /// <summary>The grants now sit under the new name.</summary>
    Renamed,

    /// <summary>No role by that name holds any grant.</summary>
    SourceNotFound,

    /// <summary>A different role already holds grants under the new name; a rename never merges two roles.</summary>
    TargetExists
}

/// <summary>Body of a role rename.</summary>
/// <param name="NewRole">The name the grants move to.</param>
public sealed record RenameRoleRequest(string NewRole);

/// <summary>Answer to a successful role rename.</summary>
/// <param name="Role">The name the grants now sit under.</param>
/// <param name="PreviousRole">The name they came from.</param>
public sealed record RoleRenameResponse(string Role, string PreviousRole);
