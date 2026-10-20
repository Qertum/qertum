namespace Qertum.IdentityService.Services;

public static class AdminAuthorization
{
    /// <summary>Folder policy for /Admin: the caller must hold the built-in admin role.</summary>
    public const string PolicyName = "IdpAdmin";
}
