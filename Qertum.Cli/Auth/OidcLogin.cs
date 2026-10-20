using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Qertum.Cli.Auth;

internal static class OidcLogin
{
    private const string CliClientId = "qca";
    private const string Scope = "openid profile roles qertum-api offline_access";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly HttpClient Http = new();

    public static async Task<CachedSession> LoginAsync(
        string identityUrl,
        string apiUrl,
        string? acrValues = null,
        int? maxAgeSeconds = null,
        CancellationToken ct = default)
    {
        identityUrl = identityUrl.TrimEnd('/');

        var discovery = await DiscoverAsync(identityUrl, ct);

        var deviceResponse = await RequestDeviceAuthorizationAsync(discovery.DeviceAuthorizationEndpoint, acrValues, maxAgeSeconds, ct);

        Console.WriteLine();
        Console.WriteLine("Open your browser to authorize this device:");
        Console.WriteLine();

        if (!string.IsNullOrEmpty(deviceResponse.VerificationUriComplete))
            Console.WriteLine($"  {deviceResponse.VerificationUriComplete}");

        Console.WriteLine();
        Console.WriteLine($"Or visit:   {deviceResponse.VerificationUri}");
        Console.WriteLine($"Enter code: {deviceResponse.UserCode}");
        Console.WriteLine();

        OpenBrowser(deviceResponse.VerificationUriComplete ?? deviceResponse.VerificationUri);

        Console.Write("Waiting for authorization");
        var tokens = await PollForTokenAsync(discovery.TokenEndpoint, deviceResponse, ct);
        Console.WriteLine(" done.");

        var username = JwtPayload.ExtractUsername(tokens.AccessToken);

        return new CachedSession
        {
            AccessToken = tokens.AccessToken,
            RefreshToken = tokens.RefreshToken,
            ExpiresAt = TimeProvider.System.GetUtcNow().AddSeconds(tokens.ExpiresIn - 30),
            IdentityUrl = identityUrl,
            ApiUrl = apiUrl,
            Username = username
        };
    }

    public static async Task<CachedSession> RefreshAsync(CachedSession session, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(session.RefreshToken))
            throw new InvalidOperationException("No refresh token. Please log in again.");

        var discovery = await DiscoverAsync(session.IdentityUrl, ct);

        var form = new FormUrlEncodedContent([
            new KeyValuePair<string, string?>("grant_type", "refresh_token"),
            new KeyValuePair<string, string?>("client_id", CliClientId),
            new KeyValuePair<string, string?>("refresh_token", session.RefreshToken)
        ]);

        var response = await Http.PostAsync(discovery.TokenEndpoint, form, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Token refresh failed ({(int)response.StatusCode}): {body}");

        var tokens = JsonSerializer.Deserialize<TokenResponse>(body, JsonOptions)
            ?? throw new InvalidOperationException("Invalid token response from server.");

        return new CachedSession
        {
            AccessToken = tokens.AccessToken,
            RefreshToken = tokens.RefreshToken ?? session.RefreshToken,
            ExpiresAt = TimeProvider.System.GetUtcNow().AddSeconds(tokens.ExpiresIn - 30),
            IdentityUrl = session.IdentityUrl,
            ApiUrl = session.ApiUrl,
            Username = JwtPayload.ExtractUsername(tokens.AccessToken)
        };
    }

    public static async Task RevokeAsync(CachedSession session, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(session.RefreshToken)) return;

        try
        {
            var discovery = await DiscoverAsync(session.IdentityUrl, ct);
            if (string.IsNullOrEmpty(discovery.RevocationEndpoint)) return;

            var form = new FormUrlEncodedContent([
                new KeyValuePair<string, string?>("token", session.RefreshToken),
                new KeyValuePair<string, string?>("token_type_hint", "refresh_token"),
                new KeyValuePair<string, string?>("client_id", CliClientId)
            ]);

            await Http.PostAsync(discovery.RevocationEndpoint, form, ct);
        }
        catch
        {
            // Best-effort — local session will be cleared regardless
        }
    }

    private static async Task<DiscoveryDocument> DiscoverAsync(string identityUrl, CancellationToken ct)
    {
        var url = $"{identityUrl}/.well-known/openid-configuration";

        var response = await Http.GetAsync(url, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"OIDC discovery failed at {url} ({(int)response.StatusCode}): {body}");

        return JsonSerializer.Deserialize<DiscoveryDocument>(body, JsonOptions)
            ?? throw new InvalidOperationException("Invalid OIDC discovery document.");
    }

    internal static IReadOnlyList<KeyValuePair<string, string?>> DeviceRequestFields(string? acrValues, int? maxAgeSeconds)
    {
        var fields = new List<KeyValuePair<string, string?>>
        {
            new("client_id", CliClientId),
            new("scope", Scope)
        };
        if (!string.IsNullOrWhiteSpace(acrValues))
            fields.Add(new("acr_values", acrValues));
        if (maxAgeSeconds is > 0)
            fields.Add(new("max_age", maxAgeSeconds.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        return fields;
    }

    private static async Task<DeviceAuthorizationResponse> RequestDeviceAuthorizationAsync(
        string deviceAuthEndpoint,
        string? acrValues,
        int? maxAgeSeconds,
        CancellationToken ct)
    {
        var form = new FormUrlEncodedContent(DeviceRequestFields(acrValues, maxAgeSeconds));

        var response = await Http.PostAsync(deviceAuthEndpoint, form, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Device authorization failed ({(int)response.StatusCode}): {body}");

        return JsonSerializer.Deserialize<DeviceAuthorizationResponse>(body, JsonOptions)
            ?? throw new InvalidOperationException("Invalid device authorization response.");
    }

    private static async Task<TokenResponse> PollForTokenAsync(
        string tokenEndpoint,
        DeviceAuthorizationResponse deviceResponse,
        CancellationToken ct)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(deviceResponse.Interval, 5));
        var expiry = TimeProvider.System.GetUtcNow().AddSeconds(deviceResponse.ExpiresIn);

        while (TimeProvider.System.GetUtcNow() < expiry)
        {
            await Task.Delay(interval, ct);
            Console.Write(".");

            var form = new FormUrlEncodedContent([
                new KeyValuePair<string, string?>("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                new KeyValuePair<string, string?>("device_code", deviceResponse.DeviceCode),
                new KeyValuePair<string, string?>("client_id", CliClientId)
            ]);

            var response = await Http.PostAsync(tokenEndpoint, form, ct);
            var body = await response.Content.ReadAsStringAsync(ct);

            if (response.IsSuccessStatusCode)
                return JsonSerializer.Deserialize<TokenResponse>(body, JsonOptions)
                    ?? throw new InvalidOperationException("Invalid token response.");

            using var errDoc = JsonDocument.Parse(body);
            var error = errDoc.RootElement.TryGetProperty("error", out var el) ? el.GetString() : null;

            switch (error)
            {
                case "authorization_pending":
                    continue;
                case "slow_down":
                    interval += TimeSpan.FromSeconds(5);
                    continue;
                case "access_denied":
                    throw new InvalidOperationException("Authorization denied by user.");
                case "expired_token":
                    throw new InvalidOperationException("Device code expired. Run login again.");
                default:
                    throw new InvalidOperationException($"Token request failed: {error ?? body}");
            }
        }

        throw new InvalidOperationException("Device code expired while waiting. Run login again.");
    }

    private static void OpenBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch
        {
            // Browser launch failed; the URL was already printed above.
        }
    }

    private sealed record DiscoveryDocument(
        [property: JsonPropertyName("authorization_endpoint")] string AuthorizationEndpoint,
        [property: JsonPropertyName("token_endpoint")] string TokenEndpoint,
        [property: JsonPropertyName("device_authorization_endpoint")] string DeviceAuthorizationEndpoint,
        [property: JsonPropertyName("end_session_endpoint")] string? EndSessionEndpoint,
        [property: JsonPropertyName("revocation_endpoint")] string? RevocationEndpoint);

    private sealed record DeviceAuthorizationResponse(
        [property: JsonPropertyName("device_code")] string DeviceCode,
        [property: JsonPropertyName("user_code")] string UserCode,
        [property: JsonPropertyName("verification_uri")] string VerificationUri,
        [property: JsonPropertyName("verification_uri_complete")] string? VerificationUriComplete,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("interval")] int Interval);

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string AccessToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn,
        [property: JsonPropertyName("token_type")] string TokenType);
}
