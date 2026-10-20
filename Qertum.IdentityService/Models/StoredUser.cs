namespace Qertum.IdentityService.Models;

public sealed class StoredUser
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Username { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;

    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Whether this account must change its password before it can be used for anything
    /// else. Set when the account was seeded with the well-known default password, or when
    /// an admin created it and chose to require a change. Cleared on a successful change.
    /// Absent from older users.json files, where it deserializes to false.
    /// </summary>
    public bool MustChangePassword { get; set; }

    /// <summary>
    /// A disabled account cannot sign in, loses its existing cookie session on the next request,
    /// and is refused at every token grant, including refresh. Absent from older users.json
    /// files, where it deserializes to false.
    /// </summary>
    public bool IsDisabled { get; set; }

    /// <summary>
    /// Rotated on every password change. Cookie sessions carry it as a claim and grants carry it
    /// as a private claim; a copy that no longer matches is a session or grant from before the
    /// change, and is signed out or refused. Absent from older users.json files, where it
    /// deserializes to empty — which still matches grants and cookies without the claim, so an
    /// upgrade signs no one out.
    /// </summary>
    public string SecurityStamp { get; set; } = string.Empty;

    /// <summary>The claim type the security stamp travels under in cookies and grants.</summary>
    public const string SecurityStampClaimType = "qertum_security_stamp";

    public static string NewSecurityStamp() => Guid.NewGuid().ToString("N");

    public List<string> Roles { get; set; } = new();
}
