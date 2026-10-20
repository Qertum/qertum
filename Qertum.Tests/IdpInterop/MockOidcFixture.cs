using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Qertum.Tests.IdpInterop;

/// <summary>
/// <c>mock-oauth2-server</c> configured so that a <c>client_credentials</c> request with <c>scope=&lt;scenario&gt;</c> returns an
/// access token with exactly the claims of that scenario: the shapes of <c>acr</c> and <c>auth_time</c> a real provider could emit.
/// </summary>
public sealed class MockOidcFixture : IAsyncDisposable
{
    public const string Image = "ghcr.io/navikt/mock-oauth2-server@sha256:f67032396f2ee4320d09389a174ef04112c754e49ce26f060050a66c1c07aedb";

    private readonly DockerContainer _container;
    private readonly HttpClient _http = new();
    private readonly int _port;

    private MockOidcFixture(DockerContainer container, int port)
    {
        _container = container;
        _port = port;
    }

    public string Authority => $"http://localhost:{_port}/default";

    public static async Task<MockOidcFixture> StartAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var baseClaims = new Dictionary<string, object?>
        {
            ["sub"] = "svc-1", ["preferred_username"] = "alice", ["role"] = new[] { "admin" }, ["aud"] = new[] { "qertum-api" }
        };
        JsonObject Scenario(string name, Dictionary<string, object?> extra)
        {
            var claims = new Dictionary<string, object?>(baseClaims);
            foreach (var (k, v) in extra)
                claims[k] = v;
            return new JsonObject
            {
                ["requestParam"] = "scope", ["match"] = name,
                ["claims"] = JsonSerializer.SerializeToNode(claims)
            };
        }

        var config = new JsonObject
        {
            ["interactiveLogin"] = false,
            ["tokenCallbacks"] = new JsonArray(new JsonObject
            {
                ["issuerId"] = "default", ["tokenExpiry"] = 3600,
                ["requestMappings"] = new JsonArray(
                    Scenario("fresh", new() { ["acr"] = "mfa", ["auth_time"] = now }),
                    Scenario("multiacr", new() { ["acr"] = new[] { "pwd", "mfa" }, ["auth_time"] = now }),
                    Scenario("stringtime", new() { ["acr"] = "mfa", ["auth_time"] = now.ToString() }),
                    Scenario("stale", new() { ["acr"] = "mfa", ["auth_time"] = now - 7200 }),
                    Scenario("future", new() { ["acr"] = "mfa", ["auth_time"] = now + 7200 }),
                    Scenario("wrongacr", new() { ["acr"] = "pwd", ["auth_time"] = now }),
                    Scenario("uppercaseacr", new() { ["acr"] = "MFA", ["auth_time"] = now }),
                    Scenario("noacr", new() { ["auth_time"] = now }),
                    Scenario("noauthtime", new() { ["acr"] = "mfa" }),
                    Scenario("floattime", new() { ["acr"] = "mfa", ["auth_time"] = now + 0.5 }))
            })
        };

        var port = DockerContainer.FreePort();
        var container = await DockerContainer.StartAsync(Image, port, 8080,
            new Dictionary<string, string> { ["SERVER_PORT"] = "8080", ["JSON_CONFIG"] = config.ToJsonString() });
        var fixture = new MockOidcFixture(container, port);
        try
        {
            await fixture.WaitUntilReadyAsync(ct);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync();
            throw;
        }
    }

    public async Task<string> TokenAsync(string scenario, CancellationToken ct)
    {
        var response = await _http.PostAsync($"{Authority}/token", new FormUrlEncodedContent(
        [
            new("grant_type", "client_credentials"), new("client_id", "c"), new("client_secret", "s"), new("scope", scenario)
        ]), ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<JsonNode>(ct))!["access_token"]!.GetValue<string>();
    }

    private async Task WaitUntilReadyAsync(CancellationToken ct)
    {
        for (var attempt = 0; attempt < 60; attempt++)
        {
            try
            {
                if ((await _http.GetAsync($"{Authority}/.well-known/openid-configuration", ct)).IsSuccessStatusCode)
                    return;
            }
            catch (HttpRequestException)
            {
                // not listening yet
            }

            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }

        throw new TimeoutException("mock-oauth2-server did not become ready. Logs:" + Environment.NewLine + await _container.LogsAsync());
    }

    public async ValueTask DisposeAsync()
    {
        _http.Dispose();
        await _container.DisposeAsync();
    }
}
