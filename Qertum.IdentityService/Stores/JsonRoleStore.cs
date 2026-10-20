using System.Text.Json;
using System.Text.RegularExpressions;
using Qertum.IdentityService.Models;

namespace Qertum.IdentityService.Stores;

public enum RoleStoreResult
{
    Success,
    InvalidName,
    AlreadyExists,
    DescriptionTooLong,
    NotFound,
    BuiltIn,
    InUse
}

/// <summary>
/// The role catalog in <c>roles.json</c>, created with only the built-in <c>admin</c> role when the
/// file is absent.
/// </summary>
public sealed partial class JsonRoleStore
{
    public const int MaxDescriptionLength = 500;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _filePath;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public JsonRoleStore(string directory)
    {
        _filePath = Path.Combine(directory, "roles.json");
        SeedIfMissing();
    }

    public string FilePath => _filePath;

    public static bool IsValidName(string? name) => name is not null && NamePattern().IsMatch(name);

    public async Task<List<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            return LoadUnlocked();
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<RoleStoreResult> CreateAsync(string name, string description, CancellationToken cancellationToken = default)
    {
        if (!IsValidName(name))
        {
            return RoleStoreResult.InvalidName;
        }

        if (description.Length > MaxDescriptionLength)
        {
            return RoleStoreResult.DescriptionTooLong;
        }

        await _lock.WaitAsync(cancellationToken);
        try
        {
            var roles = LoadUnlocked();
            if (Find(roles, name) is not null)
            {
                return RoleStoreResult.AlreadyExists;
            }

            roles.Add(new RoleDefinition { Name = name, Description = description });
            WriteUnlocked(roles);
            return RoleStoreResult.Success;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<RoleStoreResult> UpdateDescriptionAsync(string name, string description, CancellationToken cancellationToken = default)
    {
        if (description.Length > MaxDescriptionLength)
        {
            return RoleStoreResult.DescriptionTooLong;
        }

        await _lock.WaitAsync(cancellationToken);
        try
        {
            var roles = LoadUnlocked();
            var role = Find(roles, name);
            if (role is null)
            {
                return RoleStoreResult.NotFound;
            }

            role.Description = description;
            WriteUnlocked(roles);
            return RoleStoreResult.Success;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>
    /// Deletes a role unless it is built in or <paramref name="isHeld"/> reports a user still holds
    /// it. The predicate runs inside this store's lock, so a role cannot be created and deleted
    /// concurrently; it may take the user store's lock, and the user store never takes this one.
    /// </summary>
    /// <summary>
    /// Renames a role, then calls <paramref name="renameHolders"/> so every user carrying it follows.
    /// The callback runs inside this store's lock and may take the user store's lock; the user store
    /// never takes this one. Refuses a built-in role, an invalid name, and a name already in use.
    /// </summary>
    public async Task<RoleStoreResult> RenameAsync(
        string name,
        string newName,
        Func<string, string, CancellationToken, Task> renameHolders,
        CancellationToken cancellationToken = default)
    {
        if (!IsValidName(newName))
        {
            return RoleStoreResult.InvalidName;
        }

        await _lock.WaitAsync(cancellationToken);
        try
        {
            var roles = LoadUnlocked();
            var role = Find(roles, name);
            if (role is null)
            {
                return RoleStoreResult.NotFound;
            }

            if (role.BuiltIn)
            {
                return RoleStoreResult.BuiltIn;
            }

            var renamingCaseOnly = string.Equals(role.Name, newName, StringComparison.OrdinalIgnoreCase);
            if (!renamingCaseOnly && Find(roles, newName) is not null)
            {
                return RoleStoreResult.AlreadyExists;
            }

            var previousName = role.Name;
            role.Name = newName;
            WriteUnlocked(roles);
            await renameHolders(previousName, newName, cancellationToken);
            return RoleStoreResult.Success;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<RoleStoreResult> DeleteAsync(
        string name,
        Func<string, CancellationToken, Task<bool>> isHeld,
        CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var roles = LoadUnlocked();
            var role = Find(roles, name);
            if (role is null)
            {
                return RoleStoreResult.NotFound;
            }

            if (role.BuiltIn)
            {
                return RoleStoreResult.BuiltIn;
            }

            if (await isHeld(role.Name, cancellationToken))
            {
                return RoleStoreResult.InUse;
            }

            roles.Remove(role);
            WriteUnlocked(roles);
            return RoleStoreResult.Success;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static RoleDefinition? Find(IEnumerable<RoleDefinition> roles, string name) =>
        roles.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));

    private List<RoleDefinition> LoadUnlocked()
    {
        var roles = File.Exists(_filePath)
            ? JsonSerializer.Deserialize<List<RoleDefinition>>(File.ReadAllText(_filePath), SerializerOptions) ?? []
            : [];

        // A hand edit can remove admin; the catalog without it would let no one be made an admin.
        var admin = Find(roles, RoleDefinition.AdminRoleName);
        if (admin is null)
        {
            roles.Insert(0, BuiltInAdmin());
        }
        else
        {
            admin.BuiltIn = true;
        }

        var builtIn = Find(roles, RoleDefinition.AdminRoleName)!;
        foreach (var role in roles.Where(r => !ReferenceEquals(r, builtIn)))
        {
            role.BuiltIn = false;
        }

        return roles;
    }

    private void WriteUnlocked(List<RoleDefinition> roles)
    {
        var tmp = _filePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(roles, SerializerOptions));
        File.Move(tmp, _filePath, overwrite: true);
    }

    private void SeedIfMissing()
    {
        if (!File.Exists(_filePath))
        {
            WriteUnlocked([BuiltInAdmin()]);
        }
    }

    private static RoleDefinition BuiltInAdmin() => new() { Name = RoleDefinition.AdminRoleName, BuiltIn = true };

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex NamePattern();
}
