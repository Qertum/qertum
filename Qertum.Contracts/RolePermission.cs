namespace Qertum.Services;

/// <summary>RBAC row associating a permission constant with a role name.</summary>
public sealed class RolePermission
{
    /// <summary>Surrogate primary key.</summary>
    public int Id { get; init; }

    /// <summary>
    /// Role name this permission is granted to. Settable for exactly one reason: a rename moves a
    /// role's existing rows to the new spelling rather than deleting and re-inserting them, which
    /// would change which row is the lowest-Id (display) spelling.
    /// </summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>Permission constant, e.g. "certificates.view".</summary>
    public string Permission { get; init; } = string.Empty;
}
