namespace Qertum.IdentityService.Models;

/// <summary>
/// One entry in the role catalog (<c>roles.json</c>). The identity provider owns role names and
/// their descriptions; what a role grants inside the CA is decided by the CA's own
/// <c>RolePermissions</c>, which is keyed by this name — hence no rename.
/// </summary>
public sealed class RoleDefinition
{
    /// <summary>The built-in administrator role. Always present, never deletable.</summary>
    public const string AdminRoleName = "admin";

    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public bool BuiltIn { get; set; }
}
