namespace Qertum.IdentityService.Services.Audit;

public static class IdentityAuditActions
{
    public const string UserCreated = nameof(UserCreated);
    public const string UserRolesChanged = nameof(UserRolesChanged);
    public const string UserDisabled = nameof(UserDisabled);
    public const string UserEnabled = nameof(UserEnabled);
    public const string UserPasswordReset = nameof(UserPasswordReset);
    public const string UserDeleted = nameof(UserDeleted);
    public const string RoleCreated = nameof(RoleCreated);
    public const string RoleUpdated = nameof(RoleUpdated);
    public const string RoleDeleted = nameof(RoleDeleted);
    public const string RoleRenamed = nameof(RoleRenamed);
    public const string StepUpFailed = nameof(StepUpFailed);
    public const string LoginThrottled = nameof(LoginThrottled);
    public const string SecretStorageMigrated = nameof(SecretStorageMigrated);

    /// <summary>Every action name, for the audit page's filter. Adding a constant must add it here.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        UserCreated, UserRolesChanged, UserDisabled, UserEnabled, UserPasswordReset, UserDeleted,
        RoleCreated, RoleUpdated, RoleRenamed, RoleDeleted, StepUpFailed, LoginThrottled,
        SecretStorageMigrated
    ];
}
