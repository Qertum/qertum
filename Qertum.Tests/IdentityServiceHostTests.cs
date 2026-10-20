using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Hosting;

namespace Qertum.Tests;

/// <summary>
/// Boots the real identity provider host with an explicit issuer and a throwaway data path,
/// with no Aspire service discovery present. This is the production topology.
/// </summary>
public sealed class IdentityServiceHostTests : IDisposable
{
    private const string Authority = "https://idp.test";

    private readonly List<string> _tempDirectories = [];

    private string NewDataPath()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-host-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirectories.Add(dir);
        return dir;
    }

    private WebApplicationFactory<IdentityServiceProgram> CreateFactory(
        string? authority = Authority,
        string? dataPath = null,
        bool forwardedHeaders = false,
        string? secretStorageProvider = null)
    {
        var resolvedDataPath = dataPath ?? NewDataPath();

        return new WebApplicationFactory<IdentityServiceProgram>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment(Environments.Production);
                builder.UseSetting("IdentityService:DataPath", resolvedDataPath);
                builder.UseSetting("IdentityService:DisableTransportSecurity", "true");
                builder.UseSetting("ConnectionStrings:Identity",
                    $"Data Source={Path.Combine(resolvedDataPath, "identity.db")}");

                if (forwardedHeaders)
                {
                    // Configuration key behind ASPNETCORE_FORWARDEDHEADERS_ENABLED, which
                    // deploy/identity/Dockerfile sets. The generic web host reads it and wires
                    // ForwardedHeadersMiddleware for XForwardedFor | XForwardedProto.
                    builder.UseSetting("ForwardedHeaders_Enabled", "true");
                }

                if (authority is not null)
                {
                    builder.UseSetting("IdentityService:Authority", authority);
                }

                if (secretStorageProvider is not null)
                {
                    builder.UseSetting("IdentityService:SecretStorageProvider", secretStorageProvider);
                }
            });
    }

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void Startup_WithoutAuthority_FailsFastOutsideDevelopment()
    {
        using var factory = CreateFactory(authority: null);

        var ex = Assert.ThrowsAny<InvalidOperationException>(() => factory.CreateClient());

        Assert.Contains("IdentityService:Authority", ex.Message);
    }

    [Fact]
    public async Task DiscoveryDocument_AdvertisesTheConfiguredIssuer()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var document = await client.GetFromJsonAsync<JsonDocument>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.NotNull(document);
        // System.Uri stringifies a bare origin with a trailing slash (OpenIddict's SetIssuer
        // takes a Uri), so the discovery document's issuer carries one even though
        // IdentityServiceOptions.Authority itself does not.
        Assert.Equal(new Uri(Authority).ToString(), document.RootElement.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task Startup_SeedsItsFilesIntoTheConfiguredDataPath()
    {
        var dataPath = NewDataPath();
        using var factory = CreateFactory(dataPath: dataPath);
        using var client = factory.CreateClient();

        // Force the host to start before asserting on files.
        var response = await client.GetAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        Assert.True(File.Exists(Path.Combine(dataPath, "users.json")));
        Assert.True(File.Exists(Path.Combine(dataPath, "clients.json")));
        Assert.True(File.Exists(Path.Combine(dataPath, "identity.db")));
        Assert.True(Directory.Exists(Path.Combine(dataPath, "keys")));
    }

    [Fact]
    public void Startup_WithTheCloudStubSecretStorageProvider_FailsFast()
    {
        using var factory = CreateFactory(secretStorageProvider: "CloudStub");

        var ex = Assert.ThrowsAny<InvalidOperationException>(() => factory.CreateClient());

        Assert.Contains("IdentityService:SecretStorageProvider", ex.Message);
    }

    [Fact]
    public async Task Restart_NamingTheStoredSecretStorageProvider_KeepsTheSigningKeyAndMigratesNothing()
    {
        var dataPath = NewDataPath();
        string firstKeys;
        using (var factory = CreateFactory(dataPath: dataPath))
        using (var client = factory.CreateClient())
        {
            firstKeys = await client.GetStringAsync("/.well-known/jwks", TestContext.Current.CancellationToken);
        }

        using var restarted = CreateFactory(dataPath: dataPath, secretStorageProvider: "LocalFileKey");
        using var restartedClient = restarted.CreateClient();
        var secondKeys = await restartedClient.GetStringAsync("/.well-known/jwks", TestContext.Current.CancellationToken);

        Assert.Equal(firstKeys, secondKeys);
        var auditDir = Path.Combine(dataPath, "audit-logs");
        var audit = Directory.Exists(auditDir)
            ? string.Concat(Directory.EnumerateFiles(auditDir).Select(ReadShared))
            : string.Empty;
        Assert.DoesNotContain("SecretStorageMigrated", audit);
    }

    private static string ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    [Fact]
    public async Task DiscoveryDocument_AdvertisesTheGrantsClientsDependOn()
    {
        using var factory = CreateFactory();
        // Pinning BaseAddress to Authority makes the outgoing request's Host header equal
        // "idp.test", matching production topology. This is load-bearing for the assertions
        // below: OpenIddict builds token_endpoint/device_authorization_endpoint/userinfo_endpoint
        // (and, in the other tests below, the /login challenge redirect) from the *request's*
        // scheme+host combined with their configured relative paths -- not from
        // IdentityService:Authority directly. Only the "issuer" field is Authority-derived via
        // options.SetIssuer(...), and that's covered separately by
        // DiscoveryDocument_AdvertisesTheConfiguredIssuer, which uses the default (localhost)
        // client and still gets the right issuer. Without this pinning, these endpoint URLs
        // would come back rooted at whatever host WebApplicationFactory's default client uses
        // (http://localhost), not idp.test.
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(Authority)
        });

        var document = await client.GetFromJsonAsync<JsonDocument>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        var root = document!.RootElement;

        Assert.Equal($"{Authority}/connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{Authority}/connect/device_authorization",
            root.GetProperty("device_authorization_endpoint").GetString());
        Assert.Equal($"{Authority}/connect/userinfo",
            root.GetProperty("userinfo_endpoint").GetString());

        // The CLI's `auth logout` reads this from discovery and silently skips revocation when it
        // is absent, so an unadvertised endpoint means refresh tokens outlive logout.
        Assert.Equal($"{Authority}/connect/revoke", root.GetProperty("revocation_endpoint").GetString());

        var grantTypes = root.GetProperty("grant_types_supported")
            .EnumerateArray().Select(e => e.GetString()).ToArray();

        Assert.Contains("authorization_code", grantTypes);
        Assert.Contains("refresh_token", grantTypes);
        Assert.Contains("urn:ietf:params:oauth:grant-type:device_code", grantTypes);

        var challengeMethods = root.GetProperty("code_challenge_methods_supported")
            .EnumerateArray().Select(e => e.GetString()).ToArray();

        Assert.Contains("S256", challengeMethods);
    }

    [Fact]
    public async Task DiscoveryDocument_DerivesEndpointUrlsFromTheRequestNotTheAuthority()
    {
        // The behavior production depends on, isolated: the request host deliberately does NOT
        // match IdentityService:Authority (WebApplicationFactory's default client uses
        // http://localhost). SetIssuer pins only "issuer"; every endpoint URL comes from
        // OpenIddict's BaseUri, which ResolveRequestUri builds from the request's scheme, host
        // and path base. This is why a reverse proxy must forward scheme and host — see
        // DiscoveryDocument_HonoursForwardedProtoWhenForwardedHeadersAreEnabled below.
        using var factory = CreateFactory();
        using var client = factory.CreateClient();

        var document = await client.GetFromJsonAsync<JsonDocument>(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        var root = document!.RootElement;

        Assert.Equal(new Uri(Authority).ToString(), root.GetProperty("issuer").GetString());

        Assert.Equal("http://localhost/connect/authorize",
            root.GetProperty("authorization_endpoint").GetString());
        Assert.Equal("http://localhost/connect/token",
            root.GetProperty("token_endpoint").GetString());
        Assert.Equal("http://localhost/connect/device_authorization",
            root.GetProperty("device_authorization_endpoint").GetString());
        Assert.Equal("http://localhost/connect/userinfo",
            root.GetProperty("userinfo_endpoint").GetString());
        Assert.Equal("http://localhost/.well-known/jwks",
            root.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task DiscoveryDocument_HonoursForwardedProtoWhenForwardedHeadersAreEnabled()
    {
        // Proves the deploy/identity/Dockerfile setting does what its comment claims: with
        // ASPNETCORE_FORWARDEDHEADERS_ENABLED the TLS-terminating proxy's X-Forwarded-Proto
        // reaches OpenIddict's BaseUri, so advertised endpoints match the public scheme instead
        // of the plain-HTTP proxy hop. The host still comes from the Host header, which the
        // proxy has to preserve — that switch does not consume X-Forwarded-Host.
        using var factory = CreateFactory(forwardedHeaders: true);
        using var client = factory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/openid-configuration");
        request.Headers.Host = "idp.test";
        request.Headers.Add("X-Forwarded-Proto", "https");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        var document = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        var root = document!.RootElement;

        Assert.Equal($"{Authority}/connect/token", root.GetProperty("token_endpoint").GetString());
        Assert.Equal($"{Authority}/.well-known/jwks", root.GetProperty("jwks_uri").GetString());
        Assert.Equal(new Uri(Authority).ToString(), root.GetProperty("issuer").GetString());
    }

    [Fact]
    public async Task DeviceAuthorization_IssuesACodeForThePublicCliClient()
    {
        using var factory = CreateFactory();
        // See the comment on DiscoveryDocument_AdvertisesTheGrantsClientsDependOn: pinning
        // BaseAddress here is what makes verification_uri come back rooted at Authority.
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(Authority)
        });

        var response = await client.PostAsync("/connect/device_authorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = "qca",
                ["scope"] = "openid profile qertum-api"
            }),
            TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<JsonDocument>(
            TestContext.Current.CancellationToken);
        var root = payload!.RootElement;

        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("device_code").GetString()));
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("user_code").GetString()));
        Assert.StartsWith(Authority, root.GetProperty("verification_uri").GetString());
    }

    [Fact]
    public async Task AuthorizationCodeWithPkce_RedirectsAnUnauthenticatedUserToLogin()
    {
        using var factory = CreateFactory();
        // See the comment on DiscoveryDocument_AdvertisesTheGrantsClientsDependOn: pinning
        // BaseAddress here is what makes the /login redirect below come back rooted at Authority.
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(Authority)
        });

        var query =
            "?client_id=qertum-web" +
            "&response_type=code" +
            "&redirect_uri=" + Uri.EscapeDataString("https://localhost:7077/signin-oidc") +
            "&scope=" + Uri.EscapeDataString("openid profile") +
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
            "&code_challenge_method=S256" +
            "&state=abc123";

        var response = await client.GetAsync(
            "/connect/authorize" + query, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        // With the client's BaseAddress set to the configured Authority (so the request's
        // Host header matches production topology), the challenge redirect OpenIddict/ASP.NET
        // Core issues comes back as an absolute URL rooted at that Authority, not a bare path.
        Assert.StartsWith($"{Authority}/login", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task AuthorizationRequestWithoutPkce_IsRejected()
    {
        using var factory = CreateFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(Authority)
        });

        var query =
            "?client_id=qertum-web" +
            "&response_type=code" +
            "&redirect_uri=" + Uri.EscapeDataString("https://localhost:7077/signin-oidc") +
            "&scope=" + Uri.EscapeDataString("openid profile") +
            "&state=abc123";

        var response = await client.GetAsync(
            "/connect/authorize" + query, TestContext.Current.CancellationToken);

        // RequireProofKeyForCodeExchange() is on. OpenIddict rejects the request outright
        // (400, not a redirect to the login page) because the missing 'code_challenge' is a
        // request-validation failure, not an authentication concern.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains("invalid_request", body);
        Assert.Contains("code_challenge", body);
    }
}
