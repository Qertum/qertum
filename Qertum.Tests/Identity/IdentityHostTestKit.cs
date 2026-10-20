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

    public static WebApplicationFactory<IdentityServiceProgram> CreateFactory(string dataPath, TimeProvider? clock = null) =>
        new WebApplicationFactory<IdentityServiceProgram>().WithWebHostBuilder(builder =>
        {
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
        return await client.PostAsync(postUrl, new FormUrlEncodedContent(body), ct);
    }

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
        HttpClient client, string username, string password, CancellationToken ct)
    {
        using var authorization = await client.PostAsync("/connect/device_authorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = "qca",
                ["scope"] = "openid profile roles offline_access qertum-api"
            }), ct);
        authorization.EnsureSuccessStatusCode();
        var codes = (await authorization.Content.ReadFromJsonAsync<JsonDocument>(ct))!.RootElement;

        await LoginAsync(client, username, password, ct);

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
        return (tokens.GetProperty("access_token").GetString()!, tokens.GetProperty("refresh_token").GetString()!);
    }

    public static Task<HttpResponseMessage> RefreshAsync(HttpClient client, string refreshToken, CancellationToken ct) =>
        client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "qca",
            ["refresh_token"] = refreshToken
        }), ct);

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
