using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;

namespace Qertum.IdentityService.Services.Admin;

/// <summary>
/// The only path for user and role administration. Every refusal is a result, never an exception,
/// and every saved change writes exactly one audit entry; a refusal writes none.
/// </summary>
public sealed class UserAdministrationService(
    JsonUserStore users,
    JsonRoleStore roles,
    IIdentityAuditLog audit,
    IGrantRevoker grantRevoker,
    ILogger<UserAdministrationService> logger)
{
    public async Task<AdminOutcome> CreateUserAsync(
        AdminActor actor, string username, string email, string displayName,
        IReadOnlyCollection<string> requestedRoles, CancellationToken cancellationToken)
    {
        var resolved = await ResolveRolesAsync(requestedRoles, cancellationToken);
        if (resolved is null)
        {
            return new AdminOutcome(AdminResult.UnknownRole);
        }

        if (await users.FindByUsernameAsync(username, cancellationToken) is not null)
        {
            return new AdminOutcome(AdminResult.UsernameTaken);
        }

        var password = OneTimePassword.Generate();
        StoredUser created;
        try
        {
            created = await users.CreateUserAsync(username, email, displayName, password, resolved, mustChangePassword: true, cancellationToken);
        }
        catch (InvalidOperationException)
        {
            // CreateUserAsync's own uniqueness check: another admin created the name meanwhile.
            return new AdminOutcome(AdminResult.UsernameTaken);
        }

        audit.Write(IdentityAuditActions.UserCreated, actor.Username, created.Id, created.Username, $"roles: {string.Join(", ", resolved)}");
        return new AdminOutcome(AdminResult.Success, password);
    }

    public async Task<AdminOutcome> SetRolesAsync(
        AdminActor actor, Guid targetId, IReadOnlyCollection<string> requestedRoles, CancellationToken cancellationToken)
    {
        var resolved = await ResolveRolesAsync(requestedRoles, cancellationToken);
        if (resolved is null)
        {
            return new AdminOutcome(AdminResult.UnknownRole);
        }

        var target = await users.FindByIdAsync(targetId, cancellationToken);
        if (target is null)
        {
            return new AdminOutcome(AdminResult.NotFound);
        }

        if (targetId == actor.Id && HoldsAdmin(target.Roles) && !HoldsAdmin(resolved))
        {
            return new AdminOutcome(AdminResult.WouldRemoveOwnAdmin);
        }

        var result = Map(await users.MutateAsync(targetId, u => u.Roles = resolved, cancellationToken));
        if (result != AdminResult.Success)
        {
            return new AdminOutcome(result);
        }

        var added = resolved.Where(r => !target.Roles.Contains(r, StringComparer.OrdinalIgnoreCase));
        var removed = target.Roles.Where(r => !resolved.Contains(r, StringComparer.OrdinalIgnoreCase));
        audit.Write(IdentityAuditActions.UserRolesChanged, actor.Username, target.Id, target.Username,
            $"added: {string.Join(", ", added)}; removed: {string.Join(", ", removed)}");
        return new AdminOutcome(AdminResult.Success);
    }

    public async Task<AdminOutcome> SetDisabledAsync(AdminActor actor, Guid targetId, bool disabled, CancellationToken cancellationToken)
    {
        if (targetId == actor.Id)
        {
            return new AdminOutcome(AdminResult.SelfTarget);
        }

        var target = await users.FindByIdAsync(targetId, cancellationToken);
        if (target is null)
        {
            return new AdminOutcome(AdminResult.NotFound);
        }

        var result = Map(await users.MutateAsync(targetId, u => u.IsDisabled = disabled, cancellationToken));
        if (result == AdminResult.Success)
        {
            audit.Write(disabled ? IdentityAuditActions.UserDisabled : IdentityAuditActions.UserEnabled,
                actor.Username, target.Id, target.Username);
        }

        return new AdminOutcome(result);
    }

    public async Task<AdminOutcome> ResetPasswordAsync(AdminActor actor, Guid targetId, CancellationToken cancellationToken)
    {
        if (targetId == actor.Id)
        {
            return new AdminOutcome(AdminResult.SelfTarget);
        }

        var target = await users.FindByIdAsync(targetId, cancellationToken);
        if (target is null)
        {
            return new AdminOutcome(AdminResult.NotFound);
        }

        var password = OneTimePassword.Generate();
        var result = Map(await users.ResetPasswordAsync(targetId, password, cancellationToken));
        if (result != AdminResult.Success)
        {
            return new AdminOutcome(result);
        }

        audit.Write(IdentityAuditActions.UserPasswordReset, actor.Username, target.Id, target.Username);
        return new AdminOutcome(AdminResult.Success, password);
    }

    public async Task<AdminOutcome> DeleteUserAsync(AdminActor actor, Guid targetId, CancellationToken cancellationToken)
    {
        if (targetId == actor.Id)
        {
            return new AdminOutcome(AdminResult.SelfTarget);
        }

        var target = await users.FindByIdAsync(targetId, cancellationToken);
        if (target is null)
        {
            return new AdminOutcome(AdminResult.NotFound);
        }

        // Removing the user first ends access at once: every session and grant path refuses a
        // missing user. Revocation only tidies identity.db, so its failure is not rolled back —
        // that would restore access to a user an admin chose to remove.
        var result = Map(await users.RemoveAsync(targetId, cancellationToken));
        if (result != AdminResult.Success)
        {
            return new AdminOutcome(result);
        }

        var revocationFailed = false;
        try
        {
            await grantRevoker.RevokeAllAsync(targetId, cancellationToken);
        }
        catch (Exception ex)
        {
            revocationFailed = true;
            logger.LogError(ex, "Deleted user {UserId}, but revoking their stored grants failed.", targetId);
        }

        audit.Write(IdentityAuditActions.UserDeleted, actor.Username, target.Id, target.Username,
            revocationFailed ? "stored grants could not all be revoked" : null);
        return new AdminOutcome(revocationFailed ? AdminResult.DeletedButRevocationIncomplete : AdminResult.Success);
    }

    public async Task<AdminOutcome> CreateRoleAsync(AdminActor actor, string name, string description, CancellationToken cancellationToken)
    {
        var result = Map(await roles.CreateAsync(name, description, cancellationToken));
        if (result == AdminResult.Success)
        {
            audit.Write(IdentityAuditActions.RoleCreated, actor.Username, resourceName: name);
        }

        return new AdminOutcome(result);
    }

    public async Task<AdminOutcome> UpdateRoleAsync(AdminActor actor, string name, string description, CancellationToken cancellationToken)
    {
        var result = Map(await roles.UpdateDescriptionAsync(name, description, cancellationToken));
        if (result == AdminResult.Success)
        {
            audit.Write(IdentityAuditActions.RoleUpdated, actor.Username, resourceName: name);
        }

        return new AdminOutcome(result);
    }

    public async Task<AdminOutcome> RenameRoleAsync(AdminActor actor, string name, string newName, CancellationToken cancellationToken)
    {
        var result = Map(await roles.RenameAsync(name, newName, users.RenameRoleForAllAsync, cancellationToken));
        if (result == AdminResult.Success)
        {
            audit.Write(IdentityAuditActions.RoleRenamed, actor.Username, resourceName: newName, detail: $"{name} -> {newName}");
        }

        return new AdminOutcome(result);
    }

    public async Task<AdminOutcome> DeleteRoleAsync(AdminActor actor, string name, CancellationToken cancellationToken)
    {
        var result = Map(await roles.DeleteAsync(name, IsHeldAsync, cancellationToken));
        if (result == AdminResult.Success)
        {
            audit.Write(IdentityAuditActions.RoleDeleted, actor.Username, resourceName: name);
        }

        return new AdminOutcome(result);
    }

    private async Task<bool> IsHeldAsync(string role, CancellationToken cancellationToken) =>
        (await users.GetAllAsync(cancellationToken)).Any(u => u.Roles.Contains(role, StringComparer.OrdinalIgnoreCase));

    /// <summary>The catalog spelling of each requested role, de-duplicated; null if any is not in the catalog.</summary>
    private async Task<List<string>?> ResolveRolesAsync(IReadOnlyCollection<string> requested, CancellationToken cancellationToken)
    {
        var catalog = await roles.GetAllAsync(cancellationToken);
        var resolved = new List<string>();
        foreach (var name in requested)
        {
            var match = catalog.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            if (match is null)
            {
                return null;
            }

            if (!resolved.Contains(match.Name, StringComparer.Ordinal))
            {
                resolved.Add(match.Name);
            }
        }

        return resolved;
    }

    private static bool HoldsAdmin(IEnumerable<string> roleNames) =>
        roleNames.Contains(RoleDefinition.AdminRoleName, StringComparer.OrdinalIgnoreCase);

    private static AdminResult Map(UserMutationResult result) => result switch
    {
        UserMutationResult.Updated => AdminResult.Success,
        UserMutationResult.NotFound => AdminResult.NotFound,
        UserMutationResult.WouldRemoveLastAdmin => AdminResult.WouldRemoveLastAdmin,
        _ => throw new ArgumentOutOfRangeException(nameof(result), result, null)
    };

    private static AdminResult Map(RoleStoreResult result) => result switch
    {
        RoleStoreResult.Success => AdminResult.Success,
        RoleStoreResult.InvalidName => AdminResult.InvalidRoleName,
        RoleStoreResult.AlreadyExists => AdminResult.RoleExists,
        RoleStoreResult.DescriptionTooLong => AdminResult.DescriptionTooLong,
        RoleStoreResult.NotFound => AdminResult.NotFound,
        RoleStoreResult.BuiltIn => AdminResult.BuiltInRole,
        RoleStoreResult.InUse => AdminResult.RoleInUse,
        _ => throw new ArgumentOutOfRangeException(nameof(result), result, null)
    };
}
