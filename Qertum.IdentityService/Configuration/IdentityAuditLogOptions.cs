namespace Qertum.IdentityService.Configuration;

/// <summary>
/// The identity provider's own audit log of user and role administration, bound from
/// "IdentityService:AuditLog". Separate from the CA's audit log: the IdP is deployable on its own and
/// does not reference the CA's services.
/// </summary>
public sealed class IdentityAuditLogOptions
{
    /// <summary>False writes no audit file and shows an empty audit page.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Rolling CLEF file path; Serilog inserts the date before the extension. Defaults to
    /// <c>{DataPath}/audit-logs/identity-audit-.clef</c>.
    /// </summary>
    public string? Path { get; set; }
}
