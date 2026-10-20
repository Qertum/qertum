using System.Security.Claims;

namespace Qertum.IdentityService.Services.Admin;

/// <summary>The signed-in administrator performing a change.</summary>
public sealed record AdminActor(Guid Id, string Username)
{
    /// <summary>
    /// Reads the actor from the IdP cookie principal. Only called on /Admin pages, whose folder
    /// policy has already required an authenticated admin, so the subject claim is present.
    /// </summary>
    public static AdminActor From(ClaimsPrincipal user) =>
        new(Guid.Parse(user.FindFirst(ClaimTypes.NameIdentifier)!.Value), user.Identity?.Name ?? string.Empty);
}
