using System.Security.Cryptography;
using System.Text.Json;
using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Models;
using OpenIddict.Abstractions;

namespace Qertum.IdentityService.Stores;

public class JsonClientStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new() { WriteIndented = true };

    private readonly string _filePath;
    private readonly string _directory;
    private readonly ILogger<JsonClientStore> _logger;

    // When set (e.g. injected by the Aspire AppHost), this overrides the randomly
    // generated qertum-api secret so operators do not have to copy a file by hand.
    private readonly string? _configuredApiSecret;

    // Opt-in, off everywhere except the integration-test harness. These clients carry secrets
    // committed to this repository, and one of them is an admin, so seeding them anywhere else
    // hands out CA administration to anyone who can read the source.
    private readonly bool _seedTestClients;

    /// <summary>Client ids that exist only for the integration tests.</summary>
    internal static readonly string[] TestClientIds = ["qertum-test-m2m", "qertum-test-viewer"];

    public JsonClientStore(ILogger<JsonClientStore> logger, IHostApplicationLifetime lifetime,
        IdentityServiceOptions? options = null, string? directory = null)
    {
        _logger = logger;
        _configuredApiSecret = options?.ApiClientSecret;
        _seedTestClients = options?.SeedTestClients ?? false;
        _directory = directory ?? AppContext.BaseDirectory;
        Directory.CreateDirectory(_directory);
        _filePath = Path.Combine(_directory, "clients.json");
        SeedIfMissing();

        // Delete the one-time secret file once the app is fully started.
        var secretFilePath = Path.Combine(_directory, "api-client-secret.txt");
        lifetime.ApplicationStarted.Register(() =>
        {
            if (!File.Exists(secretFilePath)) return;
            try
            {
                File.Delete(secretFilePath);
                logger.LogInformation("Deleted one-time API client secret file {Path}.", secretFilePath);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to delete one-time API client secret file {Path}.", secretFilePath);
            }
        });
    }

    public string FilePath => _filePath;

    public virtual List<StoredClient> GetAll()
    {
        if (!File.Exists(_filePath))
        {
            return new List<StoredClient>();
        }
        using var fs = File.OpenRead(_filePath);
        return JsonSerializer.Deserialize<List<StoredClient>>(fs) ?? new List<StoredClient>();
    }

    private void SeedIfMissing()
    {
        if (File.Exists(_filePath))
        {
            EnsureSeedClientsPresent(_seedTestClients
                ? [BuildTestM2mClient(), BuildViewerTestClient(), BuildCliClient()]
                : [BuildCliClient()]);
            return;
        }

        var apiClientSecret = _configuredApiSecret ?? GenerateSecret();
        if (_configuredApiSecret is null)
        {
            // The API no longer introspects, so this secret is only used for the client
            // record itself. It is still written out once so an operator can recover it.
            var secretFilePath = Path.Combine(_directory, "api-client-secret.txt");
            File.WriteAllText(secretFilePath, apiClientSecret);

            _logger.LogWarning(
                "Generated API client secret at {SecretFilePath}. " +
                "The file will be deleted automatically once the application starts.",
                secretFilePath);
        }

        var seed = new List<StoredClient>
        {
            new()
            {
                ClientId = "qertum-web",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                DisplayName = "Qertum Web",
                RedirectUris =
                {
                    "https://localhost:7077/signin-oidc",
                    "http://localhost:5137/signin-oidc"
                },
                PostLogoutRedirectUris =
                {
                    "https://localhost:7077/signout-callback-oidc",
                    "http://localhost:5137/signout-callback-oidc"
                },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.Endpoints.EndSession,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles,
                    OpenIddictConstants.Permissions.Prefixes.Scope + "qertum-api"
                }
            },
            new()
            {
                ClientId = "qertum-api",
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ClientSecret = apiClientSecret,
                DisplayName = "Qertum API (resource)",
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Introspection
                }
            },
            BuildCliClient()
        };

        if (_seedTestClients)
        {
            seed.Add(BuildTestM2mClient());
            seed.Add(BuildViewerTestClient());
        }

        using (var fs = File.Create(_filePath))
        {
            JsonSerializer.Serialize(fs, seed, SerializerOptions);
        }

        _logger.LogInformation("Seeded default clients.json at {Path}", _filePath);
    }

    private static StoredClient BuildTestM2mClient() => new()
    {
        ClientId = "qertum-test-m2m",
        ClientType = OpenIddictConstants.ClientTypes.Confidential,
        ClientSecret = "test-m2m-secret",
        DisplayName = "Qertum Test M2M Client",
        Permissions =
        {
            OpenIddictConstants.Permissions.Endpoints.Token,
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            OpenIddictConstants.Permissions.Prefixes.Scope + "qertum-api"
        },
        Roles = { "admin" }
    };

    private static StoredClient BuildViewerTestClient() => new()
    {
        ClientId = "qertum-test-viewer",
        ClientType = OpenIddictConstants.ClientTypes.Confidential,
        ClientSecret = "test-viewer-secret",
        DisplayName = "Qertum Test Viewer Client",
        Permissions =
        {
            OpenIddictConstants.Permissions.Endpoints.Token,
            OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            OpenIddictConstants.Permissions.Prefixes.Scope + "qertum-api"
        },
        Roles = { "viewer" }
    };

    // Public client (no secret) for the qca CLI, named after the binary so a future sibling CLI
    // under the Qertum brand gets its own client rather than sharing this one.
    // Uses device authorization flow (RFC 8628) — no redirect URI required.
    private static StoredClient BuildCliClient() => new()
    {
        ClientId = "qca",
        ClientType = OpenIddictConstants.ClientTypes.Public,
        ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
        DisplayName = "Qertum CA CLI",
        Permissions =
        {
            OpenIddictConstants.Permissions.Endpoints.DeviceAuthorization,
            OpenIddictConstants.Permissions.Endpoints.Token,
            // `auth logout` posts the refresh token to the revocation endpoint; without this
            // OpenIddict answers unauthorized_client and the token stays live until it expires.
            OpenIddictConstants.Permissions.Endpoints.Revocation,
            OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
            OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
            OpenIddictConstants.Permissions.Scopes.Email,
            OpenIddictConstants.Permissions.Scopes.Profile,
            OpenIddictConstants.Permissions.Scopes.Roles,
            OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
            OpenIddictConstants.Permissions.Prefixes.Scope + "qertum-api"
        }
    };

    private void EnsureSeedClientsPresent(params StoredClient[] clients)
    {
        var existing = GetAll();
        var changed = false;
        foreach (var client in clients)
        {
            if (existing.Any(c => c.ClientId == client.ClientId)) continue;
            existing.Add(client);
            changed = true;
            _logger.LogInformation("Added missing seed client {ClientId} to {Path}", client.ClientId, _filePath);
        }

        changed |= RemoveTestClientsIfNotWanted(existing);

        if (!changed) return;
        using var fs = File.Create(_filePath);
        JsonSerializer.Serialize(fs, existing, SerializerOptions);
    }

    /// <summary>
    /// Strips the integration-test clients from an existing clients.json unless they are
    /// explicitly wanted. Skipping them on a fresh seed is not enough on its own: earlier
    /// versions seeded them unconditionally and back-filled them into files that lacked them, so
    /// every deployment created before this change is carrying an admin client whose secret is in
    /// the repository. Removing them here is what actually closes that.
    /// </summary>
    private bool RemoveTestClientsIfNotWanted(List<StoredClient> clients)
    {
        if (_seedTestClients) return false;

        var removed = clients.RemoveAll(c => TestClientIds.Contains(c.ClientId, StringComparer.Ordinal));
        if (removed == 0) return false;

        _logger.LogWarning(
            "Removed {Count} integration-test client(s) from {Path}. These carry secrets published " +
            "in the source and must never exist outside the test harness.",
            removed, _filePath);
        return true;
    }

    private static string GenerateSecret()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
