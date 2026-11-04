using System.Text.Json;
using Qertum.IdentityService.Models;
using Microsoft.AspNetCore.Identity;

namespace Qertum.IdentityService.Stores;

public enum UserMutationResult
{
    Updated,
    NotFound,
    WouldRemoveLastAdmin
}

public sealed class JsonUserStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    /// <summary>
    /// Well-known bootstrap password used when no <c>IdentityService:SeedAdminPassword</c>
    /// is configured. An account seeded with it carries
    /// <see cref="StoredUser.MustChangePassword"/>, so it cannot be used for anything except
    /// setting a real password.
    /// </summary>
    public const string DefaultAdminPassword = "password";

    private readonly string _filePath;
    private readonly string? _seedAdminPassword;
    private readonly bool _seedAdminPasswordMustChange;
    private readonly IPasswordHasher<StoredUser> _hasher;

    // Verified for an unknown or disabled username, so every refusal costs one hash and timing does not tell which
    // usernames exist. Made once, from a random value nobody knows.
    private static readonly string TimingEqualizerHash =
        new PasswordHasher<StoredUser>().HashPassword(new StoredUser(), Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly ILogger<JsonUserStore> _logger;

    public JsonUserStore(
        ILogger<JsonUserStore> logger,
        string? directory = null,
        string? seedAdminPassword = null,
        bool seedAdminPasswordMustChange = false)
        : this(logger, directory, seedAdminPassword, seedAdminPasswordMustChange, new PasswordHasher<StoredUser>())
    {
    }

    /// <summary>Tests pass a hasher to act between a self-service read and its write.</summary>
    internal JsonUserStore(
        ILogger<JsonUserStore> logger,
        string? directory,
        string? seedAdminPassword,
        bool seedAdminPasswordMustChange,
        IPasswordHasher<StoredUser> hasher)
    {
        _hasher = hasher;
        _logger = logger;
        _seedAdminPassword = string.IsNullOrWhiteSpace(seedAdminPassword) ? null : seedAdminPassword;
        _seedAdminPasswordMustChange = seedAdminPasswordMustChange;
        _filePath = Path.Combine(directory ?? AppContext.BaseDirectory, "users.json");
        SeedIfMissing();
    }

    public string FilePath => _filePath;

    public async Task<StoredUser?> ValidateCredentialsAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var user = await FindByUsernameAsync(username, cancellationToken);
        if (user is null || user.IsDisabled)
        {
            _ = _hasher.VerifyHashedPassword(user ?? new StoredUser(), TimingEqualizerHash, password);
            return null;
        }

        var result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed)
        {
            return null;
        }

        if (result == PasswordVerificationResult.SuccessRehashNeeded)
        {
            // Only while the stored hash is still the one just verified: an admin reset or delete meanwhile wins.
            var verifiedHash = user.PasswordHash;
            var rehashed = _hasher.HashPassword(user, password);
            await UpdateCurrentAsync(user.Id, current =>
            {
                if (current.PasswordHash != verifiedHash) return false;
                current.PasswordHash = rehashed;
                return true;
            }, cancellationToken);
            user.PasswordHash = rehashed;
        }

        return user;
    }

    public async Task<StoredUser?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var users = await LoadAsync(cancellationToken);
        return users.FirstOrDefault(u => u.Id == id);
    }

    /// <summary>
    /// The user if it still exists and is not disabled. This is the lookup every path that turns
    /// an existing session or grant back into access must use: a user deleted from users.json or
    /// disabled must stop getting in, not keep what it was given earlier.
    /// </summary>
    public async Task<StoredUser?> FindActiveByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await FindByIdAsync(id, cancellationToken);
        return user is { IsDisabled: false } ? user : null;
    }

    public async Task SetDisabledAsync(Guid id, bool disabled, CancellationToken cancellationToken = default)
    {
        ThrowIfNotUpdated(await MutateAsync(id, u => u.IsDisabled = disabled, cancellationToken));
    }

    public async Task<StoredUser?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        var users = await LoadAsync(cancellationToken);
        return users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Whether the account must change its password before it can be used. Returns false for
    /// an unknown id: callers treat an unresolvable subject through their own existing paths,
    /// and must not be sent to a change-password page for a user that does not exist.
    /// </summary>
    public async Task<bool> RequiresPasswordChangeAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var user = await FindByIdAsync(id, cancellationToken);
        return user?.MustChangePassword ?? false;
    }

    public async Task<List<StoredUser>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        return await LoadAsync(cancellationToken);
    }

    public async Task UpdateProfileAsync(Guid id, string displayName, string email, CancellationToken cancellationToken = default)
    {
        var found = await UpdateCurrentAsync(id, current =>
        {
            current.DisplayName = displayName;
            current.Email = email;
            return true;
        }, cancellationToken);
        if (!found) throw new InvalidOperationException("User not found.");
    }

    public async Task UpdateRolesAsync(Guid id, List<string> roles, CancellationToken cancellationToken = default)
    {
        ThrowIfNotUpdated(await MutateAsync(id, u => u.Roles = roles, cancellationToken));
    }

    /// <summary>
    /// Applies <paramref name="change"/> to one user inside the store lock and writes only if at
    /// least one enabled admin remains. The check has to sit inside the lock: made before it, two
    /// admins disabling each other at the same moment would both pass and leave none.
    /// </summary>
    public Task<UserMutationResult> MutateAsync(Guid id, Action<StoredUser> change, CancellationToken cancellationToken = default) =>
        WriteGuardedAsync(id, users => change(users.First(u => u.Id == id)), cancellationToken);

    /// <summary>Deletes a user under the same last-admin guard as <see cref="MutateAsync"/>.</summary>
    public Task<UserMutationResult> RemoveAsync(Guid id, CancellationToken cancellationToken = default) =>
        WriteGuardedAsync(id, users => users.RemoveAll(u => u.Id == id), cancellationToken);

    /// <summary>
    /// Admin password reset: new hash, forced change at next sign-in, and a rotated security stamp,
    /// which ends every existing session and grant for the user.
    /// </summary>
    public Task<UserMutationResult> ResetPasswordAsync(Guid id, string newPassword, CancellationToken cancellationToken = default) =>
        MutateAsync(id, u =>
        {
            u.PasswordHash = _hasher.HashPassword(u, newPassword);
            u.MustChangePassword = true;
            u.SecurityStamp = StoredUser.NewSecurityStamp();
        }, cancellationToken);

    /// <summary>Re-checks an active user's own password, for step-up. False for unknown or disabled users.</summary>
    public async Task<bool> VerifyPasswordAsync(Guid id, string password, CancellationToken cancellationToken = default)
    {
        var user = await FindActiveByIdAsync(id, cancellationToken);
        return user is not null &&
               _hasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Failed;
    }

    internal static int CountEnabledAdmins(IEnumerable<StoredUser> users) =>
        users.Count(u => !u.IsDisabled && u.Roles.Contains(RoleDefinition.AdminRoleName, StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Swaps <paramref name="oldRole"/> for <paramref name="newRole"/> on every user holding it.
    /// Called by the role store inside its own lock; this store never takes the role store's lock.
    /// </summary>
    public async Task RenameRoleForAllAsync(string oldRole, string newRole, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var users = await LoadUnlockedAsync(cancellationToken);
            foreach (var user in users)
            {
                for (var i = 0; i < user.Roles.Count; i++)
                {
                    if (string.Equals(user.Roles[i], oldRole, StringComparison.OrdinalIgnoreCase))
                        user.Roles[i] = newRole;
                }
            }

            WriteUnlocked(users);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<UserMutationResult> WriteGuardedAsync(Guid id, Action<List<StoredUser>> apply, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var users = await LoadUnlockedAsync(cancellationToken);
            if (!users.Any(u => u.Id == id))
            {
                return UserMutationResult.NotFound;
            }

            var adminsBefore = CountEnabledAdmins(users);
            apply(users);
            var adminsAfter = CountEnabledAdmins(users);

            // Refuse only a change that takes the count to zero. A file already at zero (a broken
            // hand edit) must not block unrelated changes, including re-enabling an admin.
            if (adminsAfter == 0 && adminsBefore > 0)
            {
                return UserMutationResult.WouldRemoveLastAdmin;
            }

            WriteUnlocked(users);
            return UserMutationResult.Updated;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static void ThrowIfNotUpdated(UserMutationResult result)
    {
        switch (result)
        {
            case UserMutationResult.NotFound:
                throw new InvalidOperationException("User not found.");
            case UserMutationResult.WouldRemoveLastAdmin:
                throw new InvalidOperationException("This would leave no enabled administrator.");
        }
    }

    public async Task<StoredUser> CreateUserAsync(
        string username,
        string email,
        string displayName,
        string password,
        List<string> roles,
        bool mustChangePassword = false,
        CancellationToken cancellationToken = default)
    {
        var user = new StoredUser
        {
            Username = username,
            Email = email,
            DisplayName = displayName,
            Roles = roles,
            MustChangePassword = mustChangePassword,
            SecurityStamp = StoredUser.NewSecurityStamp()
        };

        user.PasswordHash = _hasher.HashPassword(user, password);
        await AddAsync(user, cancellationToken);
        return user;
    }

    public async Task<ChangePasswordResult> ChangePasswordAsync(Guid id, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await FindByIdAsync(id, cancellationToken);
        if (user is null)
        {
            return ChangePasswordResult.UserNotFound;
        }

        var verify = _hasher.VerifyHashedPassword(user, user.PasswordHash, currentPassword);
        if (verify == PasswordVerificationResult.Failed)
        {
            return ChangePasswordResult.CurrentPasswordIncorrect;
        }

        // Without this the 8-character minimum happily accepts the well-known default as its
        // own replacement, which would defeat the forced change entirely.
        if (_hasher.VerifyHashedPassword(user, user.PasswordHash, newPassword) != PasswordVerificationResult.Failed)
        {
            return ChangePasswordResult.SameAsCurrent;
        }

        // Hashing happens outside the lock; the write applies only to the record the current password was checked
        // against. An admin reset, disable or delete in between wins: the user's old password no longer counts.
        var verifiedHash = user.PasswordHash;
        var verifiedStamp = user.SecurityStamp;
        var newHash = _hasher.HashPassword(user, newPassword);
        var newStamp = StoredUser.NewSecurityStamp();
        var applied = false;
        var found = await UpdateCurrentAsync(id, current =>
        {
            if (current.IsDisabled || current.PasswordHash != verifiedHash || current.SecurityStamp != verifiedStamp) return false;
            current.PasswordHash = newHash;
            current.MustChangePassword = false;
            // Ends every other session and grant: each carries the old stamp.
            current.SecurityStamp = newStamp;
            applied = true;
            return true;
        }, cancellationToken);
        if (!found) return ChangePasswordResult.UserNotFound;
        if (!applied) return ChangePasswordResult.CurrentPasswordIncorrect;

        user.PasswordHash = newHash;
        user.MustChangePassword = false;
        user.SecurityStamp = newStamp;
        return ChangePasswordResult.Success;
    }

    /// <summary>
    /// Self-service writes (profile, password change, rehash on sign-in) change the record as it is now, inside the lock.
    /// Replacing it with a copy read earlier undid a delete, disable, role change or reset made meanwhile, and could add a
    /// deleted user back. False when the user no longer exists; <paramref name="change"/> returns false to write nothing.
    /// </summary>
    private async Task<bool> UpdateCurrentAsync(Guid id, Func<StoredUser, bool> change, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var users = await LoadUnlockedAsync(cancellationToken);
            var current = users.FirstOrDefault(u => u.Id == id);
            if (current is null) return false;
            if (change(current)) WriteUnlocked(users);
            return true;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Adds a new user; the username check sits inside the lock so two creates cannot both pass it.</summary>
    private async Task AddAsync(StoredUser user, CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var users = await LoadUnlockedAsync(cancellationToken);
            if (users.Any(u => string.Equals(u.Username, user.Username, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("Username already exists.");
            users.Add(user);
            WriteUnlocked(users);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<List<StoredUser>> LoadAsync(CancellationToken cancellationToken)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            return await LoadUnlockedAsync(cancellationToken);
        }
        finally
        {
            _lock.Release();
        }
    }

    private async Task<List<StoredUser>> LoadUnlockedAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_filePath))
        {
            return new List<StoredUser>();
        }

        await using var fs = File.OpenRead(_filePath);
        var parsed = await JsonSerializer.DeserializeAsync<List<StoredUser>>(fs, cancellationToken: cancellationToken);
        return parsed ?? new List<StoredUser>();
    }

    private void WriteUnlocked(List<StoredUser> users)
    {
        // Create privately before writing any hashes. A unique, exclusively created path also avoids following a
        // stale or attacker-planted users.json.tmp symlink. Rename keeps readers on a complete user store.
        PrivateStoreFile.Write(_filePath, stream => JsonSerializer.Serialize(stream, users, SerializerOptions));
    }

    private void SeedIfMissing()
    {
        if (File.Exists(_filePath))
        {
            // Repair stores written by older releases without rewriting hashes or waiting for a user mutation.
            // Windows uses the data directory's inherited ACLs instead of Unix file modes.
            PrivateStoreFile.RestrictAccess(_filePath);
            return;
        }

        var admin = new StoredUser
        {
            Username = "admin",
            DisplayName = "Administrator",
            Email = "admin@localhost",
            Roles = new List<string> { "admin" }
        };

        // A configured password is the operator's deliberate secret, so it is not treated as
        // compromised. Falling back to the well-known default is, hence the forced change.
        // A provisioner that hands the password to someone else sets SeedAdminPasswordMustChange
        // so the first login replaces it with one only the new owner knows.
        var seedPassword = _seedAdminPassword ?? DefaultAdminPassword;
        admin.MustChangePassword = _seedAdminPassword is null || _seedAdminPasswordMustChange;
        admin.PasswordHash = _hasher.HashPassword(admin, seedPassword);

        WriteUnlocked(new List<StoredUser> { admin });

        if (admin.MustChangePassword)
        {
            // The value itself stays out of the log (no password is ever logged); the first-run
            // documentation names it.
            _logger.LogWarning(
                "Seeded the admin user with the well-known bootstrap password from the first-run " +
                "documentation because IdentityService:SeedAdminPassword is not configured. The " +
                "first login must change it before the account can be used.");
        }
        else
        {
            _logger.LogInformation(
                "Seeded the admin user with the configured IdentityService:SeedAdminPassword.");
        }
    }

    public enum ChangePasswordResult
    {
        Success,
        UserNotFound,
        CurrentPasswordIncorrect,
        SameAsCurrent
    }

}
