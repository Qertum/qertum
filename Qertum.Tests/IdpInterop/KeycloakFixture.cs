using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Qertum.Tests.IdpInterop;

/// <summary>
/// A real Keycloak with a realm <c>qertum</c> configured to meet Qertum's claims contract: a browser flow whose level 1 is
/// username and password and level 2 adds a one-time password, mapped to <c>acr</c> values <c>pwd</c> and <c>mfa</c>;
/// a public client <c>qertum-web</c>; an audience mapper (<c>qertum-api</c>) and a <c>role</c> claim.
/// </summary>
public sealed partial class KeycloakFixture : IAsyncDisposable
{
    public const string Image = "quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244";
    public const string OtpSecret = "JBSWY3DPEHPK3PXP";
    public const string Password = "alicepw";
    private const string Realm = "qertum";
    private const string ClientId = "qertum-web";
    private const string RedirectUri = "http://localhost/cb";

    private readonly DockerContainer _container;
    private readonly HttpClient _http = new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });

    private KeycloakFixture(DockerContainer container, int port)
    {
        _container = container;
        BaseUrl = $"http://localhost:{port}";
    }

    public string BaseUrl { get; }

    public string Authority => $"{BaseUrl}/realms/{Realm}";

    public static async Task<KeycloakFixture> StartAsync(CancellationToken ct)
    {
        var port = DockerContainer.FreePort();
        var container = await DockerContainer.StartAsync(Image, port, 8080, new Dictionary<string, string>
        {
            ["KC_BOOTSTRAP_ADMIN_USERNAME"] = "admin",
            ["KC_BOOTSTRAP_ADMIN_PASSWORD"] = "admin",
            ["KC_HOSTNAME"] = $"http://localhost:{port}",
            ["KC_HTTP_ENABLED"] = "true"
        }, "start-dev");
        var fixture = new KeycloakFixture(container, port);
        try
        {
            await fixture.WaitUntilReadyAsync(ct);
            await fixture.ConfigureRealmAsync(ct);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _http.Dispose();
        await _container.DisposeAsync();
    }

    private async Task WaitUntilReadyAsync(CancellationToken ct)
    {
        for (var attempt = 0; attempt < 90; attempt++)
        {
            try
            {
                if ((await _http.GetAsync($"{BaseUrl}/realms/master", ct)).IsSuccessStatusCode)
                    return;
            }
            catch (HttpRequestException)
            {
                // not listening yet
            }

            await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }

        throw new TimeoutException("Keycloak did not become ready. Logs:" + Environment.NewLine + await _container.LogsAsync());
    }

    // ---- administration ---------------------------------------------------------------------------------------------

    private async Task<string> AdminTokenAsync(CancellationToken ct)
    {
        var response = await _http.PostAsync($"{BaseUrl}/realms/master/protocol/openid-connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "password"), new("client_id", "admin-cli"), new("username", "admin"), new("password", "admin")
        ]), ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonNode>(ct))!["access_token"]!.GetValue<string>();
    }

    private async Task<JsonNode?> AdminAsync(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, $"{BaseUrl}/admin/realms{path}");
        request.Headers.Authorization = new("Bearer", await AdminTokenAsync(ct));
        if (body is not null)
            request.Content = JsonContent.Create(body);
        using var response = await _http.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Keycloak admin {method} {path} -> {(int)response.StatusCode}: {text}");
        return string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text);
    }

    private async Task ConfigureRealmAsync(CancellationToken ct)
    {
        var loaMap = JsonSerializer.Serialize(new Dictionary<string, string> { ["pwd"] = "1", ["mfa"] = "2" });
        await AdminAsync(HttpMethod.Post, "", new { realm = Realm, enabled = true, accessTokenLifespan = 600, attributes = new Dictionary<string, string> { ["acr.loa.map"] = loaMap } }, ct);
        await AdminAsync(HttpMethod.Post, $"/{Realm}/roles", new { name = "admin" }, ct);
        await AdminAsync(HttpMethod.Post, $"/{Realm}/clients", new
        {
            clientId = ClientId, publicClient = true, standardFlowEnabled = true, directAccessGrantsEnabled = false, fullScopeAllowed = true,
            redirectUris = new[] { "http://localhost/*" }, webOrigins = new[] { "+" },
            attributes = new Dictionary<string, string> { ["pkce.code.challenge.method"] = "S256", ["acr.loa.map"] = loaMap }
        }, ct);
        var clientUuid = (await AdminAsync(HttpMethod.Get, $"/{Realm}/clients?clientId={ClientId}", null, ct))![0]!["id"]!.GetValue<string>();
        await AdminAsync(HttpMethod.Post, $"/{Realm}/clients/{clientUuid}/protocol-mappers/models", new
        {
            name = "audience", protocol = "openid-connect", protocolMapper = "oidc-audience-mapper",
            config = new Dictionary<string, string> { ["included.custom.audience"] = "qertum-api", ["access.token.claim"] = "true", ["id.token.claim"] = "false" }
        }, ct);
        await AdminAsync(HttpMethod.Post, $"/{Realm}/clients/{clientUuid}/protocol-mappers/models", new
        {
            name = "role", protocol = "openid-connect", protocolMapper = "oidc-usermodel-realm-role-mapper",
            config = new Dictionary<string, string>
            {
                ["claim.name"] = "role", ["multivalued"] = "true", ["access.token.claim"] = "true", ["id.token.claim"] = "true", ["jsonType.label"] = "String"
            }
        }, ct);
        await BuildStepUpBrowserFlowAsync(ct);
    }

    /// <summary>Cookie, then (level 1: username+password) and (level 2: one-time password), selected by the requested acr.</summary>
    private async Task BuildStepUpBrowserFlowAsync(CancellationToken ct)
    {
        const string flow = "stepup-browser";
        await AdminAsync(HttpMethod.Post, $"/{Realm}/authentication/flows",
            new { alias = flow, providerId = "basic-flow", topLevel = true, builtIn = false, description = "LoA browser flow" }, ct);
        await AddExecutionAsync(flow, "auth-cookie", "ALTERNATIVE", ct);
        await AddSubflowAsync(flow, "stepup-forms", "ALTERNATIVE", ct);
        await AddSubflowAsync("stepup-forms", "level1", "CONDITIONAL", ct);
        var level1 = await AddExecutionAsync("level1", "conditional-level-of-authentication", "REQUIRED", ct);
        await AddExecutionAsync("level1", "auth-username-password-form", "REQUIRED", ct);
        await AddSubflowAsync("stepup-forms", "level2", "CONDITIONAL", ct);
        var level2 = await AddExecutionAsync("level2", "conditional-level-of-authentication", "REQUIRED", ct);
        await AddExecutionAsync("level2", "auth-otp-form", "REQUIRED", ct);
        await AdminAsync(HttpMethod.Post, $"/{Realm}/authentication/executions/{level1}/config", new
        {
            alias = "loa1", config = new Dictionary<string, string> { ["loa-condition-level"] = "1", ["loa-store-in-user-session"] = "true", ["loa-max-age"] = "36000" }
        }, ct);
        await AdminAsync(HttpMethod.Post, $"/{Realm}/authentication/executions/{level2}/config", new
        {
            alias = "loa2", config = new Dictionary<string, string> { ["loa-condition-level"] = "2", ["loa-store-in-user-session"] = "true", ["loa-max-age"] = "0" }
        }, ct);
        await AdminAsync(HttpMethod.Put, $"/{Realm}", new { realm = Realm, browserFlow = flow }, ct);
    }

    private async Task<string> AddExecutionAsync(string flow, string provider, string requirement, CancellationToken ct)
    {
        await AdminAsync(HttpMethod.Post, $"/{Realm}/authentication/flows/{Uri.EscapeDataString(flow)}/executions/execution", new { provider }, ct);
        return await SetRequirementAsync(flow, e => e["providerId"]?.GetValue<string>() == provider, requirement, ct);
    }

    private async Task AddSubflowAsync(string parent, string alias, string requirement, CancellationToken ct)
    {
        await AdminAsync(HttpMethod.Post, $"/{Realm}/authentication/flows/{Uri.EscapeDataString(parent)}/executions/flow",
            new { alias, type = "basic-flow", provider = "registration-page-form", description = "" }, ct);
        await SetRequirementAsync(parent, e => e["displayName"]?.GetValue<string>() == alias, requirement, ct);
    }

    private async Task<string> SetRequirementAsync(string flow, Func<JsonNode, bool> match, string requirement, CancellationToken ct)
    {
        var executions = (await AdminAsync(HttpMethod.Get, $"/{Realm}/authentication/flows/{Uri.EscapeDataString(flow)}/executions", null, ct))!.AsArray();
        // Several executions of one provider can sit in a flow; the one just added has no requirement set yet.
        var execution = executions.Last(e => match(e!))!;
        execution["requirement"] = requirement;
        await AdminAsync(HttpMethod.Put, $"/{Realm}/authentication/flows/{Uri.EscapeDataString(flow)}/executions", execution, ct);
        return execution["id"]!.GetValue<string>();
    }

    /// <summary>A new user with a password, the admin role and a TOTP credential. One user per OTP login: a code is accepted once per window.</summary>
    public async Task<string> NewUserAsync(CancellationToken ct)
    {
        var username = "user-" + Guid.NewGuid().ToString("N")[..10];
        await AdminAsync(HttpMethod.Post, $"/{Realm}/partialImport", new
        {
            ifResourceExists = "FAIL",
            users = new[]
            {
                new
                {
                    username, enabled = true, email = $"{username}@example.test", emailVerified = true, firstName = "Test", lastName = "User",
                    realmRoles = new[] { "admin" },
                    credentials = new object[]
                    {
                        new { type = "password", value = Password, temporary = false },
                        new
                        {
                            type = "otp", userLabel = "test",
                            secretData = JsonSerializer.Serialize(new { value = OtpSecret }),
                            credentialData = JsonSerializer.Serialize(new { subType = "totp", digits = 6, counter = 0, period = 30, algorithm = "HmacSHA1", secretEncoding = "BASE32" })
                        }
                    }
                }
            }
        }, ct);
        return username;
    }

    // ---- headless browser login --------------------------------------------------------------------------------------

    /// <summary>Keycloak's cookies for one browser: kept by hand, because it marks them Secure even over http://localhost.</summary>
    public sealed class Browser
    {
        public Dictionary<string, string> Cookies { get; } = [];
    }

    /// <summary>
    /// Signs <paramref name="username"/> in through the real login pages (authorization code with PKCE) and returns the access token.
    /// A password page, a password-only re-authentication page and an OTP page are all handled.
    /// </summary>
    public async Task<string> LoginAsync(string username, Browser browser, string? acrValues = null, int? maxAge = null, CancellationToken ct = default)
    {
        var verifier = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = ClientId, ["response_type"] = "code", ["redirect_uri"] = RedirectUri, ["scope"] = "openid",
            ["code_challenge"] = challenge, ["code_challenge_method"] = "S256", ["state"] = "s",
            ["acr_values"] = acrValues, ["max_age"] = maxAge?.ToString()
        };
        var url = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/auth?" + string.Join('&',
            query.Where(p => p.Value is not null).Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value!)}"));

        var (status, body, location) = await SendAsync(HttpMethod.Get, url, null, browser, ct);
        for (var step = 0; step < 8; step++)
        {
            if (location is not null && location.StartsWith(RedirectUri, StringComparison.Ordinal))
            {
                var code = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query)["code"]!;
                return await ExchangeAsync(code, verifier, ct);
            }

            if (location is not null)
            {
                (status, body, location) = await SendAsync(HttpMethod.Get, location, null, browser, ct);
                continue;
            }

            var action = FormAction().Match(body);
            if (!action.Success)
                throw new InvalidOperationException($"Keycloak answered {(int)status} with no form: {Regex.Replace(body, "<[^>]+>", " ")[..Math.Min(400, body.Length)]}");
            var target = WebUtility.HtmlDecode(action.Groups[1].Value);
            Dictionary<string, string> form;
            if (body.Contains("name=\"username\"", StringComparison.Ordinal))
                form = new() { ["username"] = username, ["password"] = Password, ["credentialId"] = "" };
            else if (body.Contains("name=\"password\"", StringComparison.Ordinal))
                form = new() { ["password"] = Password, ["credentialId"] = "" };
            else if (body.Contains("name=\"otp\"", StringComparison.Ordinal))
                form = new() { ["otp"] = Totp.Code(OtpSecret, DateTimeOffset.UtcNow), ["login"] = "Sign In" };
            else
                throw new InvalidOperationException("Keycloak showed a page this test does not know.");
            (status, body, location) = await SendAsync(HttpMethod.Post, target, form, browser, ct);
        }

        throw new InvalidOperationException("Keycloak login did not finish within eight steps.");
    }

    private async Task<string> ExchangeAsync(string code, string verifier, CancellationToken ct)
    {
        var response = await _http.PostAsync($"{BaseUrl}/realms/{Realm}/protocol/openid-connect/token", new FormUrlEncodedContent(
        [
            new("grant_type", "authorization_code"), new("client_id", ClientId), new("code", code),
            new("redirect_uri", RedirectUri), new("code_verifier", verifier)
        ]), ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        response.EnsureSuccessStatusCode();
        return JsonNode.Parse(text)!["access_token"]!.GetValue<string>();
    }

    private async Task<(HttpStatusCode Status, string Body, string? Location)> SendAsync(
        HttpMethod method, string url, Dictionary<string, string>? form, Browser browser, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        if (browser.Cookies.Count > 0)
            request.Headers.TryAddWithoutValidation("Cookie", string.Join("; ", browser.Cookies.Select(c => $"{c.Key}={c.Value}")));
        if (form is not null)
            request.Content = new FormUrlEncodedContent(form);
        using var response = await _http.SendAsync(request, ct);
        if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            foreach (var cookie in cookies)
            {
                var pair = cookie.Split(';', 2)[0];
                var separator = pair.IndexOf('=');
                var name = pair[..separator];
                var value = pair[(separator + 1)..];
                if (value.Length == 0 || cookie.Contains("Max-Age=0", StringComparison.OrdinalIgnoreCase))
                    browser.Cookies.Remove(name);
                else
                    browser.Cookies[name] = value;
            }
        }

        return (response.StatusCode, await response.Content.ReadAsStringAsync(ct), response.Headers.Location?.ToString());
    }

    [GeneratedRegex("<form[^>]*action=\"([^\"]+)\"")]
    private static partial Regex FormAction();
}
