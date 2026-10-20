using System.Net.Http.Json;
using System.Text.Json;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class AuthTokenTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-AUTH-001")]
    public async Task ClientCredentials_WithValidSecret_ReturnsToken()
    {
        using var idClient = fixture.App.CreateHttpClient("identityservice", "https");
        var resp = await idClient.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "client_credentials",
                ["client_id"]     = "qertum-test-m2m",
                ["client_secret"] = "test-m2m-secret",
                ["scope"]         = "qertum-api"
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);
        Assert.NotNull(doc);
        var root = doc.RootElement;
        var accessToken = root.GetProperty("access_token").GetString();
        Assert.NotNull(accessToken);
        Assert.NotEmpty(accessToken);
        Assert.Equal("bearer", root.GetProperty("token_type").GetString(), ignoreCase: true);
        Assert.True(root.GetProperty("expires_in").GetInt32() > 0);
    }

    [Fact(DisplayName = "IT-AUTH-002")]
    public async Task ClientCredentials_WithWrongSecret_ReturnsInvalidClientError()
    {
        using var idClient = fixture.App.CreateHttpClient("identityservice", "https");
        var resp = await idClient.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "client_credentials",
                ["client_id"]     = "qertum-test-m2m",
                ["client_secret"] = "bad-secret",
                ["scope"]         = "qertum-api"
            }), TestContext.Current.CancellationToken);

        Assert.True(
            resp.StatusCode == HttpStatusCode.BadRequest ||
            resp.StatusCode == HttpStatusCode.Unauthorized,
            $"Expected 400 or 401 but got {(int)resp.StatusCode}");
        var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);
        Assert.Equal("invalid_client", doc!.RootElement.GetProperty("error").GetString());
    }

    [Fact(DisplayName = "IT-AUTH-003")]
    public async Task ClientCredentials_JWT_ContainsExpectedClaims()
    {
        using var idClient = fixture.App.CreateHttpClient("identityservice", "https");
        var expectedIssuer = idClient.BaseAddress!.ToString().TrimEnd('/') + "/";

        var resp = await idClient.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"]    = "client_credentials",
                ["client_id"]     = "qertum-test-m2m",
                ["client_secret"] = "test-m2m-secret",
                ["scope"]         = "qertum-api"
            }), TestContext.Current.CancellationToken);
        resp.EnsureSuccessStatusCode();
        var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>(TestContext.Current.CancellationToken);
        var token = doc!.RootElement.GetProperty("access_token").GetString()!;

        var payload = TestHelpers.DecodeJwtPayload(token);

        Assert.Equal(expectedIssuer, payload.GetProperty("iss").GetString());
        Assert.Equal("qertum-test-m2m", payload.GetProperty("sub").GetString());

        var audElement = payload.GetProperty("aud");
        var audiences = audElement.ValueKind == JsonValueKind.Array
            ? audElement.EnumerateArray().Select(e => e.GetString()).ToList()
            : new List<string?> { audElement.GetString() };
        Assert.Contains("qertum-api", audiences);

        var roleElement = payload.GetProperty("role");
        var roles = roleElement.ValueKind == JsonValueKind.Array
            ? roleElement.EnumerateArray().Select(e => e.GetString()).ToList()
            : new List<string?> { roleElement.GetString() };
        Assert.Contains("admin", roles);
    }

    [Fact(DisplayName = "IT-AUTH-004")]
    public async Task AdminToken_ApiCall_ProvesBearerIntrospectionActive()
    {
        var response = await fixture.ApiClientAsAdmin.GetAsync("/v1/certificate-requests", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
