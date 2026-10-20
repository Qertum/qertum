namespace Qertum.IdentityService.Services.Admin;

/// <summary>
/// The only text an admin page shows for an outcome. Fixed strings, so no exception message or
/// internal detail can reach the page.
/// </summary>
public static class AdminMessages
{
    public const string Unexpected = "Something went wrong. The change was not saved.";

    public static string For(AdminResult result) => result switch
    {
        AdminResult.Success => "Saved.",
        AdminResult.NotFound => "That user or role no longer exists.",
        AdminResult.UsernameTaken => "That username is already taken.",
        AdminResult.UnknownRole => "One or more selected roles are not in the role catalog.",
        AdminResult.InvalidRoleName => "Role names are 1–64 characters: letters, digits, dot, dash or underscore.",
        AdminResult.RoleExists => "A role with that name already exists.",
        AdminResult.DescriptionTooLong => "Descriptions are limited to 500 characters.",
        AdminResult.SelfTarget => "You cannot do this to your own account.",
        AdminResult.WouldRemoveOwnAdmin => "You cannot remove your own admin role.",
        AdminResult.WouldRemoveLastAdmin => "This would leave no enabled administrator.",
        AdminResult.BuiltInRole => "The admin role is built in and cannot be deleted.",
        AdminResult.RoleInUse => "This role is still assigned to at least one user. Remove it from them first.",
        AdminResult.DeletedButRevocationIncomplete =>
            "The user was deleted, but some of their stored grants could not be revoked. " +
            "Those grants cannot be used, because the user no longer exists.",
        _ => Unexpected
    };
}
