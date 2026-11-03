using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Qertum.Tests.Identity;

/// <summary>Boots the real identity provider for admin page tests and drives its forms.</summary>
internal static partial class IdentityHostTestKit
{
    public const string Authority = "https://idp.test";

    public const string DeviceFlowScope = "openid profile roles offline_access qertum-api";

    /// <param name="seedTestClients">Seeds <c>qertum-test-m2m</c> and <c>qertum-test-viewer</c> (committed secrets, so opt-in).</param>
    public static WebApplicationFactory<IdentityServiceProgram> CreateFactory(
        string dataPath, TimeProvider? clock = null, bool seedTestClients = false) =>
        ConfiguredFactory.Create<IdentityServiceProgram>(builder =>
        {
            if (seedTestClients)
            {
                builder.UseSetting("IdentityService:SeedTestClients", "true");
            }
            builder.UseEnvironment(Environments.Production);
            builder.UseSetting("IdentityService:Authority", Authority);
            builder.UseSetting("IdentityService:DataPath", dataPath);
            builder.UseSetting("IdentityService:DisableTransportSecurity", "true");
            builder.UseSetting("ConnectionStrings:Identity", $"Data Source={Path.Combine(dataPath, "identity.db")}");
            if (clock is not null)
            {
                builder.ConfigureTestServices(services => services.AddSingleton(clock));
            }
        });

    public static HttpClient CreateClient(WebApplicationFactory<IdentityServiceProgram> factory) =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri(Authority)
        });

    public static async Task<string> GetAntiforgeryTokenAsync(HttpClient client, string pageUrl, CancellationToken ct)
    {
        using var page = await client.GetAsync(pageUrl, ct);
        Assert.True(page.StatusCode == HttpStatusCode.OK, $"GET {pageUrl} answered {(int)page.StatusCode}.");
        var match = AntiforgeryTokenPattern().Match(await page.Content.ReadAsStringAsync(ct));
        Assert.True(match.Success, $"{pageUrl} rendered no antiforgery token.");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    /// <summary>Scrapes an antiforgery token from <paramref name="tokenPageUrl"/>, then posts the form.</summary>
    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient client, string tokenPageUrl, string postUrl,
        IEnumerable<KeyValuePair<string, string>> fields, CancellationToken ct)
    {
        var token = await GetAntiforgeryTokenAsync(client, tokenPageUrl, ct);
        var body = fields.Append(KeyValuePair.Create("__RequestVerificationToken", token));
        using var form = new FormUrlEncodedContent(body);
        return await client.PostAsync(postUrl, form, ct);
    }

    /// <summary>Opens the device confirmation page for <paramref name="userCode"/> and posts its Allow form.</summary>
    public static Task<HttpResponseMessage> ApproveDeviceAsync(HttpClient client, string userCode, CancellationToken ct) =>
        PostFormAsync(client, $"/connect/verify?user_code={Uri.EscapeDataString(userCode)}", "/connect/verify",
            [KeyValuePair.Create("user_code", userCode)], ct);

    public static async Task LoginAsync(HttpClient client, string username, string password, CancellationToken ct)
    {
        using var response = await PostFormAsync(client, "/login", "/login",
            [KeyValuePair.Create("Input.Username", username), KeyValuePair.Create("Input.Password", password)], ct);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    public static async Task ConfirmStepUpAsync(HttpClient client, string password, CancellationToken ct)
    {
        using var response = await PostFormAsync(client, "/Admin/Confirm", "/Admin/Confirm",
            [KeyValuePair.Create("Password", password)], ct);
        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
    }

    public static async Task<(string AccessToken, string RefreshToken)> ObtainTokensViaDeviceFlowAsync(
        HttpClient client, string username, string password, CancellationToken ct, string scope = DeviceFlowScope)
    {
        using var form2 = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = "qca",
                ["scope"] = scope
            });
        using var authorization = await client.PostAsync("/connect/device_authorization",
            form2, ct);
        authorization.EnsureSuccessStatusCode();
        var codes = (await authorization.Content.ReadFromJsonAsync<JsonDocument>(ct))!.RootElement;

        await LoginAsync(client, username, password, ct);

        // Approve through the confirmation page, which carries the antiforgery token the POST needs.
        using var verify = await ApproveDeviceAsync(client, codes.GetProperty("user_code").GetString()!, ct);
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = "qca",
                ["device_code"] = codes.GetProperty("device_code").GetString()!
            });
        using var token = await client.PostAsync("/connect/token",
            form, ct);
        var body = await token.Content.ReadAsStringAsync(ct);
        Assert.True(token.StatusCode == HttpStatusCode.OK, body);
        var tokens = JsonDocument.Parse(body).RootElement;
        return (tokens.GetProperty("access_token").GetString()!, tokens.GetProperty("refresh_token").GetString()!);
    }

    public static async Task<HttpResponseMessage> RefreshAsync(HttpClient client, string refreshToken, CancellationToken ct)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "qca",
            ["refresh_token"] = refreshToken
        });
        return await client.PostAsync("/connect/token", form, ct);
    }

    public static async Task AssertInvalidGrantAsync(HttpResponseMessage response, CancellationToken ct)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<JsonDocument>(ct))!.RootElement;
        Assert.Equal("invalid_grant", body.GetProperty("error").GetString());
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryTokenPattern();

    [GeneratedRegex("data-testid=\"one-time-password\"[\\s\\S]*?<div class=\"readonly mono\">([^<]+)</div>")]
    public static partial Regex OneTimePasswordPattern();
}
