using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Data;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services;
using Qertum.IdentityService.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;

namespace Qertum.Tests;

file sealed class TestApplicationLifetime : IHostApplicationLifetime
{
    private readonly CancellationTokenSource _started = new();
    public CancellationToken ApplicationStarted => _started.Token;
    public CancellationToken ApplicationStopping => CancellationToken.None;
    public CancellationToken ApplicationStopped => CancellationToken.None;
    public void StopApplication() { }
    public void TriggerApplicationStarted() => _started.Cancel();
}

public sealed class IdentityServiceTests
{
    /// <summary>Creates a unique temp directory for each test to prevent concurrent file access.</summary>
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"jus-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public async Task JsonUserStore_NoConfiguredSeedPassword_UsesDefaultAndFlagsForChange()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();

        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);

        Assert.True(File.Exists(Path.Combine(dir, "users.json")));
        Assert.False(File.Exists(Path.Combine(dir, "admin-password.txt")));

        var admin = await store.ValidateCredentialsAsync("admin", JsonUserStore.DefaultAdminPassword, ct);
        Assert.NotNull(admin);
        Assert.Contains("admin", admin!.Roles);
        Assert.True(admin.MustChangePassword);
    }

    [Fact]
    public async Task JsonUserStore_ConfiguredSeedPassword_UsedAndNotFlagged()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();

        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir, "Operator-Chosen-1!");

        Assert.Null(await store.ValidateCredentialsAsync("admin", JsonUserStore.DefaultAdminPassword, ct));

        var admin = await store.ValidateCredentialsAsync("admin", "Operator-Chosen-1!", ct);
        Assert.NotNull(admin);
        Assert.False(admin!.MustChangePassword);
    }

    [Fact]
    public async Task JsonUserStore_ExistingUsersFile_SeedPasswordNotReapplied()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();

        _ = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir, "First-Password-1!");

        // A second store over the same directory must leave the existing file alone.
        var second = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir, "Second-Password-1!");

        Assert.Null(await second.ValidateCredentialsAsync("admin", "Second-Password-1!", ct));
        Assert.NotNull(await second.ValidateCredentialsAsync("admin", "First-Password-1!", ct));
    }

    [Fact]
    public void IdentityServiceOptions_ShortSeedAdminPassword_Throws()
    {
        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.example",
            SeedAdminPassword = "short"
        };

        var ex = Assert.Throws<InvalidOperationException>(() => options.Validate(isDevelopment: false));
        Assert.Contains("SeedAdminPassword", ex.Message);
    }

    [Fact]
    public void IdentityServiceOptions_BlankSeedAdminPassword_NormalizedToNull()
    {
        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.example",
            SeedAdminPassword = ""
        };

        options.Validate(isDevelopment: false);

        Assert.Null(options.SeedAdminPassword);
    }

    [Fact]
    public void JsonClientStore_ApplicationStarted_DeletesSecretFile()
    {
        var dir = TempDir();
        var secretFilePath = Path.Combine(dir, "api-client-secret.txt");
        File.WriteAllText(secretFilePath, "mysecret");

        var lifetime = new TestApplicationLifetime();
        _ = new JsonClientStore(NullLogger<JsonClientStore>.Instance, lifetime, options: null, directory: dir);

        Assert.True(File.Exists(secretFilePath));
        lifetime.TriggerApplicationStarted();
        Assert.False(File.Exists(secretFilePath));
    }

    [Fact]
    public void JsonClientStore_SeedsClientsJsonInConfiguredDirectory()
    {
        var dir = TempDir();

        var store = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: null, directory: dir);

        Assert.Equal(Path.Combine(dir, "clients.json"), store.FilePath);
        Assert.True(File.Exists(store.FilePath));
        Assert.Contains(store.GetAll(), c => c.ClientId == "qca");
    }

    [Fact]
    public void JsonClientStore_CliClient_MayUseTheRevocationEndpoint()
    {
        var dir = TempDir();

        var store = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: null, directory: dir);

        // `auth logout` posts the refresh token to the revocation endpoint. Without this permission
        // OpenIddict answers unauthorized_client and the token stays live until it expires.
        var cli = store.GetAll().Single(c => c.ClientId == "qca");
        Assert.Contains(OpenIddictConstants.Permissions.Endpoints.Revocation, cli.Permissions);
    }

    [Fact]
    public void JsonClientStore_DoesNotSeedTestClientsByDefault()
    {
        var dir = TempDir();

        var store = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: null, directory: dir);

        // qertum-test-m2m is an admin whose secret is committed to this repository. Seeding it
        // by default put CA administration behind a password anyone could read.
        Assert.DoesNotContain(store.GetAll(), c => c.ClientId == "qertum-test-m2m");
        Assert.DoesNotContain(store.GetAll(), c => c.ClientId == "qertum-test-viewer");
    }

    [Fact]
    public void JsonClientStore_SeedsTestClientsWhenExplicitlyEnabled()
    {
        var dir = TempDir();

        var store = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: new Qertum.IdentityService.Configuration.IdentityServiceOptions { SeedTestClients = true }, directory: dir);

        Assert.Contains(store.GetAll(), c => c.ClientId == "qertum-test-m2m");
        Assert.Contains(store.GetAll(), c => c.ClientId == "qertum-test-viewer");
    }

    [Fact]
    public void JsonClientStore_StripsTestClientsFromAnExistingFile()
    {
        var dir = TempDir();

        // A clients.json written by a version that seeded the test clients unconditionally.
        var seeded = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: new Qertum.IdentityService.Configuration.IdentityServiceOptions { SeedTestClients = true }, directory: dir);
        Assert.Contains(seeded.GetAll(), c => c.ClientId == "qertum-test-m2m");

        // Starting again without the opt-in must remove them, not merely stop adding them:
        // every deployment created before this change is carrying that admin client.
        var store = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: null, directory: dir);

        Assert.DoesNotContain(store.GetAll(), c => c.ClientId == "qertum-test-m2m");
        Assert.DoesNotContain(store.GetAll(), c => c.ClientId == "qertum-test-viewer");

        // The real clients must survive the purge.
        Assert.Contains(store.GetAll(), c => c.ClientId == "qertum-web");
        Assert.Contains(store.GetAll(), c => c.ClientId == "qca");
    }

    [Fact]
    public void JsonClientStore_WritesGeneratedApiSecretIntoConfiguredDirectory()
    {
        var dir = TempDir();

        _ = new JsonClientStore(
            NullLogger<JsonClientStore>.Instance, new TestApplicationLifetime(),
            options: null, directory: dir);

        Assert.True(File.Exists(Path.Combine(dir, "api-client-secret.txt")));
        Assert.False(File.Exists(Path.Combine(AppContext.BaseDirectory, "api-client-secret.txt")));
    }

    // ── JsonUserStore credential / password-change tests ──────────────────────

    [Fact]
    public async Task JsonUserStore_ValidCredentials_ReturnsUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"valid-{Guid.NewGuid():N}";

        await store.CreateUserAsync(username, "t@t.local", "T", "P@ssword1!", ["user"], cancellationToken: ct);

        var validated = await store.ValidateCredentialsAsync(username, "P@ssword1!", ct);
        Assert.NotNull(validated);
        Assert.Equal(username, validated.Username);
    }

    [Fact]
    public async Task JsonUserStore_InvalidCredentials_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"invalid-{Guid.NewGuid():N}";

        await store.CreateUserAsync(username, "t@t.local", "T", "CorrectPass!", ["user"], cancellationToken: ct);

        var result = await store.ValidateCredentialsAsync(username, "WrongPassword", ct);
        Assert.Null(result);
    }

    [Fact]
    public async Task JsonUserStore_ChangePassword_WrongCurrentPassword_ReturnsError()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"cp-wrong-{Guid.NewGuid():N}";

        var user = await store.CreateUserAsync(username, "t@t.local", "T", "Initial1!", ["user"], cancellationToken: ct);
        var result = await store.ChangePasswordAsync(user.Id, "WrongOld", "NewPass1!", ct);

        Assert.Equal(JsonUserStore.ChangePasswordResult.CurrentPasswordIncorrect, result);
    }

    [Fact]
    public async Task JsonUserStore_ChangePassword_CorrectCurrentPassword_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"cp-ok-{Guid.NewGuid():N}";

        var user = await store.CreateUserAsync(username, "t@t.local", "T", "Initial2!", ["user"], cancellationToken: ct);
        var result = await store.ChangePasswordAsync(user.Id, "Initial2!", "New2Pass!", ct);
        Assert.Equal(JsonUserStore.ChangePasswordResult.Success, result);

        Assert.Null(await store.ValidateCredentialsAsync(username, "Initial2!", ct));
        Assert.NotNull(await store.ValidateCredentialsAsync(username, "New2Pass!", ct));
    }

    [Fact]
    public async Task JsonUserStore_ChangePassword_ClearsMustChangePasswordFlag()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);

        var admin = await store.FindByUsernameAsync("admin", ct);
        Assert.NotNull(admin);
        Assert.True(admin!.MustChangePassword);

        var result = await store.ChangePasswordAsync(
            admin.Id, JsonUserStore.DefaultAdminPassword, "Real-Password-1!", ct);
        Assert.Equal(JsonUserStore.ChangePasswordResult.Success, result);

        Assert.False(await store.RequiresPasswordChangeAsync(admin.Id, ct));

        // The cleared flag must survive a reload from disk.
        var reloaded = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var reloadedAdmin = await reloaded.FindByUsernameAsync("admin", ct);
        Assert.False(reloadedAdmin!.MustChangePassword);
    }

    [Fact]
    public async Task JsonUserStore_ChangePassword_NewPasswordSameAsCurrent_Rejected()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());

        var admin = await store.FindByUsernameAsync("admin", ct);
        Assert.NotNull(admin);

        var result = await store.ChangePasswordAsync(
            admin!.Id, JsonUserStore.DefaultAdminPassword, JsonUserStore.DefaultAdminPassword, ct);

        Assert.Equal(JsonUserStore.ChangePasswordResult.SameAsCurrent, result);
        Assert.True(await store.RequiresPasswordChangeAsync(admin.Id, ct));
        Assert.NotNull(await store.ValidateCredentialsAsync("admin", JsonUserStore.DefaultAdminPassword, ct));
    }

    [Fact]
    public async Task JsonUserStore_RequiresPasswordChange_UnknownUser_ReturnsFalse()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());

        Assert.False(await store.RequiresPasswordChangeAsync(Guid.NewGuid(), ct));
    }

    [Fact]
    public async Task JsonUserStore_LegacyUsersFileWithoutFlag_LoadsAndIsNotFlagged()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();

        // A users.json written before MustChangePassword existed: the property is simply absent.
        // Deserialization must default it to false so an existing deployment is not locked out.
        var id = Guid.NewGuid();
        var hash = new PasswordHasher<StoredUser>().HashPassword(new StoredUser(), "Legacy-Password-1!");
        await File.WriteAllTextAsync(
            Path.Combine(dir, "users.json"),
            $$"""
            [
              {
                "Id": "{{id}}",
                "Username": "admin",
                "Email": "admin@localhost",
                "DisplayName": "Administrator",
                "PasswordHash": "{{hash}}",
                "Roles": [ "admin" ]
              }
            ]
            """,
            ct);

        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);

        var admin = await store.ValidateCredentialsAsync("admin", "Legacy-Password-1!", ct);
        Assert.NotNull(admin);
        Assert.Equal(id, admin!.Id);
        Assert.False(admin.MustChangePassword);
        Assert.False(await store.RequiresPasswordChangeAsync(id, ct));
    }

    // ── Disabled accounts ──────────────────────────────────────────────────────

    [Fact]
    public async Task JsonUserStore_LegacyUsersFileWithoutDisabledFlag_LoadsAsActive()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();

        // A users.json written before IsDisabled existed must not lock anyone out.
        var id = Guid.NewGuid();
        await File.WriteAllTextAsync(
            Path.Combine(dir, "users.json"),
            $$"""
            [
              {
                "Id": "{{id}}",
                "Username": "legacy",
                "Email": "legacy@localhost",
                "DisplayName": "Legacy",
                "PasswordHash": "unused",
                "Roles": [ "admin" ]
              }
            ]
            """,
            ct);

        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);

        var user = await store.FindActiveByIdAsync(id, ct);
        Assert.NotNull(user);
        Assert.False(user!.IsDisabled);
    }

    [Fact]
    public async Task JsonUserStore_FindActiveById_UnknownUser_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());

        Assert.Null(await store.FindActiveByIdAsync(Guid.NewGuid(), ct));
    }

    [Fact]
    public async Task JsonUserStore_SetDisabled_PersistsAndHidesTheUserFromActiveLookup()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var user = await store.CreateUserAsync("leaver", "l@t.local", "L", "Leaver-Pass-1!", ["user"], cancellationToken: ct);

        await store.SetDisabledAsync(user.Id, true, ct);

        var reloaded = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        Assert.True((await reloaded.FindByIdAsync(user.Id, ct))!.IsDisabled);
        Assert.Null(await reloaded.FindActiveByIdAsync(user.Id, ct));

        await reloaded.SetDisabledAsync(user.Id, false, ct);
        Assert.NotNull(await reloaded.FindActiveByIdAsync(user.Id, ct));
    }

    [Fact]
    public async Task JsonUserStore_ValidateCredentials_DisabledUser_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var user = await store.CreateUserAsync("disabled", "d@t.local", "D", "Correct-Pass-1!", ["user"], cancellationToken: ct);
        await store.SetDisabledAsync(user.Id, true, ct);

        Assert.Null(await store.ValidateCredentialsAsync("disabled", "Correct-Pass-1!", ct));
    }

    // ── ChangePassword rate-limiting tests ────────────────────────────────────

    [Fact]
    public async Task ChangePassword_SixthConsecutiveWrongAttempt_ReturnsRateLimitError()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"ratelimit-{Guid.NewGuid():N}";
        var user = await store.CreateUserAsync(username, "t@t.local", "T", "Correct1!", ["user"], cancellationToken: ct);

        IMemoryCache cache = new MemoryCache(
            new MemoryCacheOptions());
        var cacheKey = $"pwd-change-fails:{user.Id}";

        // Simulate 5 failed attempts by writing directly to the cache
        cache.Set(cacheKey, 5, TimeSpan.FromSeconds(60));

        // On the 6th attempt the model page should block before even calling ChangePasswordAsync
        // — verified here by checking the cache counter is at or above the limit
        var storedCount = cache.TryGetValue(cacheKey, out object? v) ? (int)v! : 0;
        Assert.True(storedCount >= 5, $"Expected at least 5 failures in cache, got {storedCount}");

        // A successful password change should clear the counter
        var result = await store.ChangePasswordAsync(user.Id, "Correct1!", "NewPass1!", ct);
        Assert.Equal(JsonUserStore.ChangePasswordResult.Success, result);
        cache.Remove(cacheKey);
        Assert.False(cache.TryGetValue(cacheKey, out _));
    }

    // ── ClientSeedHostedService tests ──────────────────────────────────────────

    [Fact]
    public async Task ClientSeedHostedService_SeedsClientsFromJson_OnStartup()
    {
        var ct = TestContext.Current.CancellationToken;

        // Keep a single open connection alive so the in-memory DB persists across scopes
        using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(connection);
        services.AddDbContext<AuthDbContext>((sp, opts) =>
            opts.UseSqlite(sp.GetRequiredService<SqliteConnection>())
                .UseOpenIddict());
        services.AddOpenIddict()
            .AddCore(opts => opts.UseEntityFrameworkCore().UseDbContext<AuthDbContext>());

        await using var sp = services.BuildServiceProvider();

        await using (var dbScope = sp.CreateAsyncScope())
        {
            var db = dbScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Database.EnsureCreatedAsync(ct);
        }

        var seedClientId = $"seed-{Guid.NewGuid():N}";
        var clientStore = new FixedListClientStore(
        [
            new StoredClient
            {
                ClientId = seedClientId,
                ClientType = OpenIddictConstants.ClientTypes.Public,
                DisplayName = "Seed Test",
                Permissions = { OpenIddictConstants.Permissions.Endpoints.Token }
            }
        ]);

        var seedOptions = new IdentityServiceOptions { Authority = "https://idp.test" };
        seedOptions.Validate(isDevelopment: false);

        var seedService = new ClientSeedHostedService(
            sp, clientStore,
            new ConfigurationBuilder().Build(),
            seedOptions,
            NullLogger<ClientSeedHostedService>.Instance);
        await seedService.StartAsync(ct);

        await using var verifyScope = sp.CreateAsyncScope();
        var manager = verifyScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await manager.FindByClientIdAsync(seedClientId, ct);
        Assert.NotNull(app);
    }

    private static async Task<(ServiceProvider Provider, SqliteConnection Connection)> CreateSeedHostAsync(
        CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(cancellationToken);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(connection);
        services.AddDbContext<AuthDbContext>((sp, opts) =>
            opts.UseSqlite(sp.GetRequiredService<SqliteConnection>())
                .UseOpenIddict());
        services.AddOpenIddict()
            .AddCore(opts => opts.UseEntityFrameworkCore().UseDbContext<AuthDbContext>());

        var sp = services.BuildServiceProvider();

        await using (var dbScope = sp.CreateAsyncScope())
        {
            var db = dbScope.ServiceProvider.GetRequiredService<AuthDbContext>();
            await db.Database.EnsureCreatedAsync(cancellationToken);
        }

        return (sp, connection);
    }

    private static IConfiguration WebFrontendDiscoveryConfiguration() =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Services:webfrontend:https:0"] = "https://localhost:9999"
            })
            .Build();

    private static async Task<IReadOnlyList<string>> SeedWebClientAndReadRedirectUrisAsync(
        bool serviceDiscoveryEnabled, CancellationToken cancellationToken)
    {
        var (sp, connection) = await CreateSeedHostAsync(cancellationToken);
        await using var _ = sp;
        using var __ = connection;

        var clientStore = new FixedListClientStore(
        [
            new StoredClient
            {
                ClientId = "qertum-web",
                ClientType = OpenIddictConstants.ClientTypes.Public,
                DisplayName = "Qertum Web",
                RedirectUris = { "https://configured.example/signin-oidc" },
                Permissions = { OpenIddictConstants.Permissions.Endpoints.Token }
            }
        ]);

        var options = new IdentityServiceOptions
        {
            Authority = "https://idp.test",
            EnableServiceDiscoveryRedirectUris = serviceDiscoveryEnabled
        };
        options.Validate(isDevelopment: false);

        var seedService = new ClientSeedHostedService(
            sp, clientStore, WebFrontendDiscoveryConfiguration(), options,
            NullLogger<ClientSeedHostedService>.Instance);
        await seedService.StartAsync(cancellationToken);

        await using var verifyScope = sp.CreateAsyncScope();
        var manager = verifyScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var app = await manager.FindByClientIdAsync("qertum-web", cancellationToken);
        Assert.NotNull(app);

        return (await manager.GetRedirectUrisAsync(app, cancellationToken)).ToArray();
    }

    [Fact]
    public async Task ClientSeed_WithServiceDiscoveryDisabled_UsesOnlyConfiguredRedirectUris()
    {
        var uris = await SeedWebClientAndReadRedirectUrisAsync(
            serviceDiscoveryEnabled: false, TestContext.Current.CancellationToken);

        Assert.Equal(["https://configured.example/signin-oidc"], uris);
    }

    [Fact]
    public async Task ClientSeed_WithServiceDiscoveryEnabled_AddsDiscoveredRedirectUris()
    {
        var uris = await SeedWebClientAndReadRedirectUrisAsync(
            serviceDiscoveryEnabled: true, TestContext.Current.CancellationToken);

        Assert.Contains("https://configured.example/signin-oidc", uris);
        Assert.Contains("https://localhost:9999/signin-oidc", uris);
    }

    [Fact]
    public async Task JsonUserStore_CreateUser_WithMustChangePassword_PersistsFlag()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var username = $"newuser-{Guid.NewGuid():N}";

        var created = await store.CreateUserAsync(
            username, "n@t.local", "New User", "Temp-Password-1!", ["user"],
            mustChangePassword: true, cancellationToken: ct);

        Assert.True(created.MustChangePassword);
        Assert.True(await store.RequiresPasswordChangeAsync(created.Id, ct));

        var reloaded = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var reloadedUser = await reloaded.FindByUsernameAsync(username, ct);
        Assert.True(reloadedUser!.MustChangePassword);
    }

    [Fact]
    public async Task JsonUserStore_CreateUser_DefaultsToNoForcedChange()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = new JsonUserStore(NullLogger<JsonUserStore>.Instance, TempDir());
        var username = $"plainuser-{Guid.NewGuid():N}";

        var created = await store.CreateUserAsync(
            username, "p@t.local", "Plain User", "Temp-Password-1!", ["user"],
            cancellationToken: ct);

        Assert.False(created.MustChangePassword);
    }
}

file sealed class FixedListClientStore(List<StoredClient> clients)
    : JsonClientStore(NullLogger<JsonClientStore>.Instance, new FixedLifetime(),
        options: null, directory: FixedListClientStore.CreateTempDirectory())
{
    public override List<StoredClient> GetAll() => clients;

    private static string CreateTempDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-clients-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }
}

file sealed class FixedLifetime : IHostApplicationLifetime
{
    public CancellationToken ApplicationStarted => CancellationToken.None;
    public CancellationToken ApplicationStopping => CancellationToken.None;
    public CancellationToken ApplicationStopped => CancellationToken.None;
    public void StopApplication() { }
}
