using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Qertum.IdentityService.Stores;
using Qertum.Tests.Identity;

namespace Qertum.Tests;

/// <summary>
/// Boots the real identity provider and checks that a change to a stored user — a role removed,
/// the account disabled, the account deleted from users.json, or the password changed — reaches sessions and refresh
/// tokens that already exist, rather than waiting for them to expire.
/// </summary>
public sealed partial class IdentityAccessRevocationHostTests : IDisposable
{
    private const string Authority = "https://idp.test";
    private const string Password = "Revocation-Test-1!";

    private readonly List<string> _tempDirectories = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task RefreshToken_AfterRoleChange_CarriesTheCurrentRoles()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("demoted", "d@t.local", "D", Password, ["admin"], cancellationToken: ct);

        var (accessToken, refreshToken) = await ObtainTokensViaDeviceFlowAsync(client, "demoted", ct);
        Assert.Contains("admin", RolesIn(accessToken));

        await store.UpdateRolesAsync(user.Id, ["viewer"], ct);

        using var response = await RefreshAsync(client, refreshToken, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var refreshed = await response.Content.ReadFromJsonAsync<JsonDocument>(ct);
        Assert.Equal(["viewer"], RolesIn(refreshed!.RootElement.GetProperty("access_token").GetString()!));
    }

    [Fact]
    public async Task RefreshToken_AfterUserDisabled_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("disabled", "d@t.local", "D", Password, ["viewer"], cancellationToken: ct);

        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(client, "disabled", ct);

        await store.SetDisabledAsync(user.Id, true, ct);

        using var response = await RefreshAsync(client, refreshToken, ct);
        await AssertInvalidGrantAsync(response, ct);
    }

    [Fact]
    public async Task RefreshToken_AfterUserDeletedFromUsersFile_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("deleted", "d@t.local", "D", Password, ["viewer"], cancellationToken: ct);

        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(client, "deleted", ct);

        // Removing the entry by hand is how an operator deletes a user today.
        var remaining = (await store.GetAllAsync(ct)).Where(u => u.Id != user.Id).ToList();
        await File.WriteAllTextAsync(store.FilePath, JsonSerializer.Serialize(remaining), ct);

        using var response = await RefreshAsync(client, refreshToken, ct);
        await AssertInvalidGrantAsync(response, ct);
    }

    [Fact]
    public async Task CookieSession_AfterAdminRoleRemoved_LosesTheUsersPage()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("formeradmin", "f@t.local", "F", Password, ["admin"], cancellationToken: ct);

        await LoginAsync(client, "formeradmin", ct);
        await IdentityHostTestKit.ConfirmStepUpAsync(client, Password, ct);
        using (var before = await client.GetAsync("/Admin/Users", ct))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        await store.UpdateRolesAsync(user.Id, [], ct);

        using var after = await client.GetAsync("/Admin/Users", ct);
        Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
    }

    [Fact]
    public async Task CookieSession_AfterUserDisabled_IsSignedOut()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("leaver", "l@t.local", "L", Password, ["viewer"], cancellationToken: ct);

        await LoginAsync(client, "leaver", ct);
        using (var before = await client.GetAsync("/Account", ct))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        await store.SetDisabledAsync(user.Id, true, ct);

        using var after = await client.GetAsync("/Account", ct);
        Assert.Equal(HttpStatusCode.Found, after.StatusCode);
        Assert.Contains("/login", after.Headers.Location!.OriginalString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Login_DisabledUser_IsRefusedWithTheGenericMessage()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("blocked", "b@t.local", "B", Password, ["viewer"], cancellationToken: ct);
        await store.SetDisabledAsync(user.Id, true, ct);

        using var response = await PostLoginAsync(client, "blocked", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Invalid username or password.", await response.Content.ReadAsStringAsync(ct));
    }

    [Fact]
    public async Task RefreshToken_AfterPasswordChange_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("rotator", "r@t.local", "R", Password, ["viewer"], cancellationToken: ct);

        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(client, "rotator", ct);

        Assert.Equal(JsonUserStore.ChangePasswordResult.Success,
            await store.ChangePasswordAsync(user.Id, Password, "Rotated-Password-2!", ct));

        using var response = await RefreshAsync(client, refreshToken, ct);
        await AssertInvalidGrantAsync(response, ct);
    }

    [Fact]
    public async Task PasswordChange_SignsOutOtherSessions_ButKeepsTheOneThatChangedIt()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var changer = CreateClient(factory);
        using var other = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        await store.CreateUserAsync("twodevices", "t@t.local", "T", Password, ["viewer"], cancellationToken: ct);

        await LoginAsync(changer, "twodevices", ct);
        await LoginAsync(other, "twodevices", ct);

        using (var page = await changer.GetAsync("/Account/ChangePassword", ct))
        {
            page.EnsureSuccessStatusCode();
            var antiforgery = AntiforgeryTokenPattern().Match(await page.Content.ReadAsStringAsync(ct));
            Assert.True(antiforgery.Success, "The change-password page rendered no antiforgery token.");

            using var change = await changer.PostAsync("/Account/ChangePassword", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Input.CurrentPassword"] = Password,
                ["Input.NewPassword"] = "Rotated-Password-2!",
                ["Input.ConfirmPassword"] = "Rotated-Password-2!",
                ["__RequestVerificationToken"] = WebUtility.HtmlDecode(antiforgery.Groups[1].Value)
            }), ct);
            Assert.Equal(HttpStatusCode.OK, change.StatusCode);
            Assert.Contains("Password updated.", await change.Content.ReadAsStringAsync(ct));
        }

        using var otherAfter = await other.GetAsync("/Account", ct);
        Assert.Equal(HttpStatusCode.Found, otherAfter.StatusCode);
        Assert.Contains("/login", otherAfter.Headers.Location!.OriginalString, StringComparison.OrdinalIgnoreCase);

        using var changerAfter = await changer.GetAsync("/Account", ct);
        Assert.Equal(HttpStatusCode.OK, changerAfter.StatusCode);
    }

    [Fact]
    public async Task UserWithoutSecurityStamp_StillSignsInAndRefreshes()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var user = await store.CreateUserAsync("legacy", "l@t.local", "L", Password, ["viewer"], cancellationToken: ct);

        // users.json written before security stamps existed has no such property.
        var users = (await store.GetAllAsync(ct)).ToList();
        users.Single(u => u.Id == user.Id).SecurityStamp = string.Empty;
        await File.WriteAllTextAsync(store.FilePath, JsonSerializer.Serialize(users), ct);

        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(client, "legacy", ct);
        using (var account = await client.GetAsync("/Account", ct))
        {
            Assert.Equal(HttpStatusCode.OK, account.StatusCode);
        }

        using var response = await RefreshAsync(client, refreshToken, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private WebApplicationFactory<IdentityServiceProgram> CreateFactory()
    {
        var dataPath = Path.Combine(Path.GetTempPath(), $"idp-revoke-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataPath);
        _tempDirectories.Add(dataPath);

        return new WebApplicationFactory<IdentityServiceProgram>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment(Environments.Production);
                builder.UseSetting("IdentityService:Authority", Authority);
                builder.UseSetting("IdentityService:DataPath", dataPath);
                builder.UseSetting("IdentityService:DisableTransportSecurity", "true");
                builder.UseSetting("ConnectionStrings:Identity",
                    $"Data Source={Path.Combine(dataPath, "identity.db")}");
            });
    }

    private static HttpClient CreateClient(WebApplicationFactory<IdentityServiceProgram> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(Authority)
        });

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient client, string username, CancellationToken ct)
    {
        using var page = await client.GetAsync("/login", ct);
        page.EnsureSuccessStatusCode();
        var html = await page.Content.ReadAsStringAsync(ct);
        var antiforgery = AntiforgeryTokenPattern().Match(html);
        Assert.True(antiforgery.Success, "The login page rendered no antiforgery token.");

        return await client.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Input.Username"] = username,
            ["Input.Password"] = Password,
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(antiforgery.Groups[1].Value)
        }), ct);
    }

    private static async Task LoginAsync(HttpClient client, string username, CancellationToken ct)
    {
        using var response = await PostLoginAsync(client, username, ct);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    private static async Task<(string AccessToken, string RefreshToken)> ObtainTokensViaDeviceFlowAsync(
        HttpClient client, string username, CancellationToken ct)
    {
        using var authorization = await client.PostAsync("/connect/device_authorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = "qca",
                ["scope"] = "openid profile roles offline_access qertum-api"
            }), ct);
        authorization.EnsureSuccessStatusCode();
        var codes = (await authorization.Content.ReadFromJsonAsync<JsonDocument>(ct))!.RootElement;

        await LoginAsync(client, username, ct);

        using var verify = await client.PostAsync("/connect/verify",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["user_code"] = codes.GetProperty("user_code").GetString()!
            }), ct);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        using var token = await client.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = "qca",
                ["device_code"] = codes.GetProperty("device_code").GetString()!
            }), ct);
        var body = await token.Content.ReadAsStringAsync(ct);
        Assert.True(token.StatusCode == HttpStatusCode.OK, body);
        var tokens = JsonDocument.Parse(body).RootElement;
        Assert.True(tokens.TryGetProperty("refresh_token", out var refreshToken), $"No refresh token issued: {body}");

        return (tokens.GetProperty("access_token").GetString()!, refreshToken.GetString()!);
    }

    private static Task<HttpResponseMessage> RefreshAsync(HttpClient client, string refreshToken, CancellationToken ct) =>
        client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "qca",
            ["refresh_token"] = refreshToken
        }), ct);

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response, CancellationToken ct)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonDocument>(ct))!.RootElement;
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    /// <summary>The role claim of an unencrypted JWT access token, whether one value or many.</summary>
    private static string[] RolesIn(string jwt)
    {
        var payload = jwt.Split('.')[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));

        if (!doc.RootElement.TryGetProperty("role", out var role))
        {
            return [];
        }

        return role.ValueKind == JsonValueKind.Array
            ? role.EnumerateArray().Select(r => r.GetString()!).ToArray()
            : [role.GetString()!];
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryTokenPattern();
}
