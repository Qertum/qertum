using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Qertum.Web.Auth;

/// <summary>How an IdP back-channel call ended.</summary>
public enum OidcCallOutcome
{
    Success,

    /// <summary>
    /// The IdP refused the grant or the token (<c>400</c>/<c>401</c>): the user is gone, disabled,
    /// or the grant was revoked. The session must end.
    /// </summary>
    Rejected,

    /// <summary>The IdP could not be asked (network error, timeout, <c>5xx</c>). Try again later.</summary>
    Unavailable
}

public sealed record TokenRefreshResult(
    OidcCallOutcome Outcome,
    string? AccessToken = null,
    string? RefreshToken = null,
    int? ExpiresIn = null);

public sealed record UserInfoResult(OidcCallOutcome Outcome, IReadOnlyList<Claim> Claims);

/// <summary>
/// The Web app's two back-channel calls to the IdP: redeeming a refresh token and reading
/// <c>userinfo</c>. Shared by <see cref="CircuitTokenAccessor"/> and <see cref="CookieRoleRevalidator"/>.
/// <para>
/// OpenIddict rotates refresh tokens, so a token redeemed twice is a replay. Concurrent requests
/// carrying the same cookie would each try to redeem it, while each circuit keeps its own
/// captured token set. <see cref="RefreshAsync"/> therefore shares one
/// redemption per refresh token and remembers its result for <see cref="ReuseWindow"/>, so a
/// caller still holding the old token receives the tokens it was exchanged for instead of
/// redeeming it again.
/// </para>
/// </summary>
public sealed class OidcTokenClient(
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
    IHttpClientFactory httpClientFactory,
    TimeProvider timeProvider,
    ILogger<OidcTokenClient> logger)
{
    public const string HttpClientName = "oidc-refresh";

    internal static readonly TimeSpan ReuseWindow = TimeSpan.FromSeconds(30);

    /// <summary>User claims <c>connect/userinfo</c> returns; these replace the principal's copies.</summary>
    public static readonly IReadOnlySet<string> UserInfoClaimTypes =
        new HashSet<string>(StringComparer.Ordinal) { "name", "preferred_username", "given_name", "email", "role" };

    private readonly ConcurrentDictionary<string, (Task<TokenRefreshResult> Task, DateTimeOffset Expires)> _redemptions = new(StringComparer.Ordinal);

    public Task<TokenRefreshResult> RefreshAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        foreach (var (key, cached) in _redemptions)
        {
            if (cached.Expires <= now && cached.Task.IsCompleted)
                _redemptions.TryRemove(key, out _);
        }

        // The redemption must not be cancelled by whichever caller happened to start it.
        var entry = _redemptions.GetOrAdd(
            refreshToken,
            token => (RedeemAsync(token, CancellationToken.None), now + ReuseWindow));

        return entry.Task.WaitAsync(cancellationToken);
    }

    public async Task<UserInfoResult> GetUserInfoAsync(string accessToken, CancellationToken cancellationToken)
    {
        try
        {
            var endpoints = await ResolveEndpointsAsync(cancellationToken);
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoints.UserInfo);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using var response = await httpClientFactory.CreateClient(HttpClientName).SendAsync(request, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return new UserInfoResult(OidcCallOutcome.Rejected, []);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("userinfo returned {StatusCode}.", response.StatusCode);
                return new UserInfoResult(OidcCallOutcome.Unavailable, []);
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var claims = new List<Claim>();
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (!UserInfoClaimTypes.Contains(property.Name))
                    continue;

                var values = property.Value.ValueKind == JsonValueKind.Array
                    ? property.Value.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : null)
                    : [property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null];

                claims.AddRange(values
                    .Where(v => !string.IsNullOrEmpty(v))
                    .Select(v => new Claim(property.Name, v!)));
            }

            return new UserInfoResult(OidcCallOutcome.Success, claims);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "userinfo call failed.");
            return new UserInfoResult(OidcCallOutcome.Unavailable, []);
        }
    }

    private async Task<TokenRefreshResult> RedeemAsync(string refreshToken, CancellationToken cancellationToken)
    {
        try
        {
            var endpoints = await ResolveEndpointsAsync(cancellationToken);
            var clientId = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme).ClientId!;

            using var response = await httpClientFactory.CreateClient(HttpClientName).PostAsync(endpoints.Token, new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = clientId,
                    ["refresh_token"] = refreshToken
                }), cancellationToken);

            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
            {
                logger.LogWarning("Token refresh refused with {StatusCode}.", response.StatusCode);
                return new TokenRefreshResult(OidcCallOutcome.Rejected);
            }
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Token refresh returned {StatusCode}.", response.StatusCode);
                return new TokenRefreshResult(OidcCallOutcome.Unavailable);
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = doc.RootElement;

            var accessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null;
            if (string.IsNullOrEmpty(accessToken))
                return new TokenRefreshResult(OidcCallOutcome.Unavailable);

            var newRefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : null;
            int? expiresIn = root.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : null;

            logger.LogInformation("Access token refreshed successfully.");
            return new TokenRefreshResult(OidcCallOutcome.Success, accessToken, newRefreshToken, expiresIn);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Exception during token refresh attempt.");
            return new TokenRefreshResult(OidcCallOutcome.Unavailable);
        }
    }

    private async Task<(string Token, string UserInfo)> ResolveEndpointsAsync(CancellationToken cancellationToken)
    {
        var options = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);

        // Configuration is only populated once the handler has run in this process; a cookie that
        // outlived a restart reaches here first, so load the discovery document if needed.
        OpenIdConnectConfiguration? configuration = options.Configuration;
        if (configuration is null && options.ConfigurationManager is not null)
            configuration = await options.ConfigurationManager.GetConfigurationAsync(cancellationToken);

        var authority = options.Authority?.TrimEnd('/');
        return (
            configuration?.TokenEndpoint
                ?? throw new InvalidOperationException($"The OIDC discovery document of '{authority}' has no token_endpoint; Qertum does not guess one."),
            configuration?.UserInfoEndpoint
                ?? throw new InvalidOperationException($"The OIDC discovery document of '{authority}' has no userinfo_endpoint; Qertum does not guess one."));
    }
}
