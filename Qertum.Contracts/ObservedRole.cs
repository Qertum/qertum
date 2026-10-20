namespace Qertum.Services;

/// <summary>
/// A role name the API has seen in a bearer token. Holds the name and when it was seen — never who
/// carried it. Lets the roles page flag grants no user can currently hold.
/// </summary>
public sealed class ObservedRole
{
    /// <summary>Role name as first seen; compared case-insensitively (NOCASE).</summary>
    public string Role { get; set; } = string.Empty;

    /// <summary>First time a token carrying this role reached the API (UTC).</summary>
    public DateTime FirstSeenUtc { get; set; }

    /// <summary>Most recent recorded sighting (UTC), accurate to the recorder's throttle window.</summary>
    public DateTime LastSeenUtc { get; set; }
}
