namespace Qertum.IdentityService.Services.Admin;

public enum AdminResult
{
    Success,
    NotFound,
    UsernameTaken,
    UnknownRole,
    InvalidRoleName,
    RoleExists,
    DescriptionTooLong,
    SelfTarget,
    WouldRemoveOwnAdmin,
    WouldRemoveLastAdmin,
    BuiltInRole,
    RoleInUse,
    DeletedButRevocationIncomplete
}

/// <param name="OneTimePassword">Set only by create and reset. Show it once; never store or log it.</param>
public sealed record AdminOutcome(AdminResult Result, string? OneTimePassword = null)
{
    /// <summary>True when the change was saved, including a delete whose grant cleanup failed.</summary>
    public bool Succeeded => Result is AdminResult.Success or AdminResult.DeletedButRevocationIncomplete;
}
