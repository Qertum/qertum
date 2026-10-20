namespace Qertum.Services;

public interface IRolePermissionService
{
    Task<IReadOnlyList<string>> GetPermissionsForRoleAsync(string role, CancellationToken cancellationToken = default);

    Task<IReadOnlyDictionary<string, IReadOnlyList<string>>> GetAllRolePermissionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces the role's permissions. Audits and raises <c>RolePermissionsUpdated</c> unless nothing
    /// changed. Throws <see cref="ArgumentException"/> for an invalid role name, the admin role, or
    /// unknown permissions, writing nothing.
    /// </summary>
    Task<RolePermissionChange> SetPermissionsForRoleAsync(string role, IEnumerable<string> permissions, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Moves a role's grants to <paramref name="newRole"/>, keeping the new spelling. Audits and
    /// raises <c>RolePermissionsRenamed</c>. Throws <see cref="ArgumentException"/> for an invalid
    /// name on either side or for the admin role. Observed-role history is deliberately untouched.
    /// </summary>
    Task<RoleRenameOutcome> RenameRoleAsync(string role, string newRole, string performedBy, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<string>> GetEffectivePermissionsAsync(IEnumerable<string> roles, CancellationToken cancellationToken = default);
}
