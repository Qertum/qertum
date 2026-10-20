namespace Qertum.Services;

/// <summary>
/// What the CA accepts as a role name. Looser than the IdentityService catalog pattern
/// (<c>^[A-Za-z0-9._-]{1,64}$</c>), which is a strict subset, so roles from other OIDC providers
/// (spaces, colons) still fit. <c>/</c> is refused because the name travels as a route segment.
/// </summary>
public static class RoleNameRules
{
    /// <summary>Longest accepted role name.</summary>
    public const int MaxLength = 128;

    /// <summary>Whether <paramref name="role"/> is an acceptable role name.</summary>
    public static bool IsValid(string? role) => TryValidate(role, out _);

    /// <summary>Validates <paramref name="role"/>; on failure <paramref name="error"/> names the rule broken.</summary>
    public static bool TryValidate(string? role, out string? error)
    {
        error = role switch
        {
            null or "" => "Role name is required.",
            _ when role.Length > MaxLength => $"Role name must be at most {MaxLength} characters.",
            _ when role.Trim().Length != role.Length => "Role name must not start or end with whitespace.",
            _ when role.Any(char.IsControl) => "Role name must not contain control characters.",
            _ when role.Contains('/') => "Role name must not contain '/'.",
            _ => null
        };
        return error is null;
    }
}
