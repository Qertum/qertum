using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// The API accepts an access token when its audience is <c>qertum-api</c>. The identity provider used to add that
/// audience to every token, so a client that signed in without asking for the <c>qertum-api</c> scope (an app that
/// wanted only the user's profile) still got a token the API accepted with the user's roles.
/// The audience now follows the granted scope, on every grant that mints a token.
/// </summary>
public sealed class ApiAudienceTests : IDisposable
{
    private const string Password = "Api-Audience-Test-1!";
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "qertum-audience-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dataPath, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("qertum-api", true)]
    [InlineData("", false)]
    public async Task ClientCredentials_CarryTheApiAudienceOnlyWithTheApiScope(string scope, bool expectAudience)
    {
        await using var factory = IdentityHostTestKit.CreateFactory(_dataPath, seedTestClients: true);
        using var client = IdentityHostTestKit.CreateClient(factory);

        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "qertum-test-m2m",
            ["client_secret"] = "test-m2m-secret"
        };
        if (scope.Length > 0) fields["scope"] = scope;
        using var form = new FormUrlEncodedContent(fields);
        using var response = await client.PostAsync("/connect/token", form, Ct);
        var body = await response.Content.ReadAsStringAsync(Ct);
        Assert.True(response.IsSuccessStatusCode, body);

        var accessToken = JsonDocument.Parse(body).RootElement.GetProperty("access_token").GetString()!;
        Assert.Equal(expectAudience, Audiences(accessToken).Contains("qertum-api"));
    }

    [Theory]
    [InlineData(IdentityHostTestKit.DeviceFlowScope, true)]
    [InlineData("openid profile roles offline_access", false)]
    public async Task UserTokens_CarryTheApiAudienceOnlyWithTheApiScope_AlsoAfterRefresh(string scope, bool expectAudience)
    {
        await using var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        using var client = IdentityHostTestKit.CreateClient(factory);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("reader", "r@t.local", "R", Password, ["admin"], cancellationToken: Ct);

        var (accessToken, refreshToken) =
            await IdentityHostTestKit.ObtainTokensViaDeviceFlowAsync(client, "reader", Password, Ct, scope);
        Assert.Equal(expectAudience, Audiences(accessToken).Contains("qertum-api"));

        using var refreshed = await IdentityHostTestKit.RefreshAsync(client, refreshToken, Ct);
        var body = await refreshed.Content.ReadFromJsonAsync<JsonDocument>(Ct);
        var refreshedToken = body!.RootElement.GetProperty("access_token").GetString()!;
        Assert.Equal(expectAudience, Audiences(refreshedToken).Contains("qertum-api"));
    }

    private static string[] Audiences(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var claims = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload))).RootElement;
        if (!claims.TryGetProperty("aud", out var aud)) return [];
        return aud.ValueKind == JsonValueKind.Array
            ? aud.EnumerateArray().Select(a => a.GetString()!).ToArray()
            : [aud.GetString()!];
    }
}
