namespace Qertum.IdentityService.Services.Audit;

/// <summary>
/// Records one completed user or role administration change. Never pass a password, one-time
/// password, hash or security stamp in any argument.
/// </summary>
public interface IIdentityAuditLog
{
    void Write(string action, string performedBy, Guid? resourceId = null, string? resourceName = null, string? detail = null);
}
