namespace Qertum.Services.BulkOperations;

/// <summary>Who may use which bulk operation. The routes decide the permission by kind because it depends on the body.</summary>
public static class BulkOperationAccess
{
    /// <summary>The single-item permission a kind needs: revoke is <c>certificates.manage</c>, renew <c>certificates.create</c>.</summary>
    /// <param name="kind">The operation kind.</param>
    /// <returns>The permission name.</returns>
    public static string PermissionFor(BulkOperationKind kind) => kind switch
    {
        BulkOperationKind.Revoke => AppPermissions.CertificatesManage,
        BulkOperationKind.Renew => AppPermissions.CertificatesCreate,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown bulk operation kind.")
    };

    /// <summary>The creator (by subject, or by name for a legacy operation without one) or an admin.</summary>
    /// <param name="operation">The operation.</param>
    /// <param name="actor">The caller.</param>
    /// <returns>True when the caller may read or cancel it.</returns>
    public static bool CanSee(BulkOperationView operation, BulkActor actor) =>
        actor.IsAdmin
        || (operation.CreatedBySubject is { } subject
            ? string.Equals(subject, actor.Subject, StringComparison.Ordinal)
            : string.Equals(operation.CreatedBy, actor.Name, StringComparison.Ordinal));
}
