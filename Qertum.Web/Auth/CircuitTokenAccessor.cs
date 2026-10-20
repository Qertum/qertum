using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Qertum.Web.Auth;

/// <summary>Supplies access tokens owned by the current request or circuit scope.</summary>
public interface ICircuitTokens
{
    /// <summary>The scope's access token, refreshed when near expiry; null when none is usable.</summary>
    Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default);

    /// <summary>Refreshes the token used by a request that the API refused with 401.</summary>
    Task<string?> RefreshAfterUnauthorizedAsync(
        string rejectedAccessToken, CancellationToken cancellationToken = default);
}

/// <summary>
/// Captures one request's tokens during rendering and keeps them in that request or circuit scope.
/// Refreshes are serialized within the scope. No pooled HTTP handler owns these tokens.
/// </summary>
public sealed class CircuitTokenAccessor(
    IHttpContextAccessor httpContextAccessor,
    OidcTokenClient tokenClient,
    TimeProvider timeProvider,
    ILogger<CircuitTokenAccessor> logger) : ICircuitTokens
{
    private static readonly TimeSpan RefreshLeeway = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    private string? _accessToken;
    private string? _refreshToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MaxValue;

    /// <summary>Replaces tokens from a live HTTP request; leaves this circuit alone when context is absent.</summary>
    public async Task CaptureAsync(CancellationToken cancellationToken = default)
    {
        var context = httpContextAccessor.HttpContext;
        if (context is null)
            return;

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (context.User.Identity?.IsAuthenticated != true)
            {
                Clear();
                return;
            }

            _accessToken = EmptyToNull(await context.GetTokenAsync("access_token"));
            _refreshToken = EmptyToNull(await context.GetTokenAsync("refresh_token"));
            var expiresAt = await context.GetTokenAsync("expires_at");
            _expiresAt = DateTimeOffset.TryParse(expiresAt, out var parsed)
                ? parsed
                : DateTimeOffset.MaxValue;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_accessToken))
            return null;
        if (timeProvider.GetUtcNow() < _expiresAt - RefreshLeeway || string.IsNullOrEmpty(_refreshToken))
            return _accessToken;

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (string.IsNullOrEmpty(_accessToken))
                return null;
            if (timeProvider.GetUtcNow() < _expiresAt - RefreshLeeway || string.IsNullOrEmpty(_refreshToken))
                return _accessToken;

            return await RedeemCurrentRefreshTokenAsync(cancellationToken) ?? _accessToken;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<string?> RefreshAfterUnauthorizedAsync(
        string rejectedAccessToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_accessToken))
            return null;

        await _refreshGate.WaitAsync(cancellationToken);
        try
        {
            if (string.IsNullOrEmpty(_accessToken))
                return null;
            if (_accessToken != rejectedAccessToken)
                return _accessToken;
            if (string.IsNullOrEmpty(_refreshToken))
                return null;

            return await RedeemCurrentRefreshTokenAsync(cancellationToken);
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private async Task<string?> RedeemCurrentRefreshTokenAsync(CancellationToken cancellationToken)
    {
        var spentRefresh = _refreshToken!;
        var result = await tokenClient.RefreshAsync(spentRefresh, cancellationToken);
        if (result.Outcome == OidcCallOutcome.Unavailable)
            return null;
        if (result.Outcome == OidcCallOutcome.Rejected)
        {
            Clear();
            logger.LogInformation("IdP refused this scope's refresh token.");
            await SignOutCurrentSsrCookieIfMutableAsync(spentRefresh);
            return null;
        }

        _accessToken = EmptyToNull(result.AccessToken);
        _refreshToken = EmptyToNull(result.RefreshToken) ?? spentRefresh;
        if (result.ExpiresIn is { } expiresIn)
            _expiresAt = timeProvider.GetUtcNow().AddSeconds(expiresIn);

        await PersistCurrentSsrCookieIfMutableAsync(spentRefresh, result);
        return _accessToken;
    }

    private async Task PersistCurrentSsrCookieIfMutableAsync(string spentRefresh, TokenRefreshResult result)
    {
        var context = httpContextAccessor.HttpContext;
        if (context is null || context.Response.HasStarted)
            return;

        var auth = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (auth.Principal is null || auth.Properties?.GetTokenValue("refresh_token") != spentRefresh)
            return;

        var values = auth.Properties.GetTokens().ToDictionary(token => token.Name, token => token.Value,
            StringComparer.Ordinal);
        values["access_token"] = result.AccessToken!;
        if (!string.IsNullOrEmpty(result.RefreshToken))
            values["refresh_token"] = result.RefreshToken;
        if (result.ExpiresIn is { } expiresIn)
            values["expires_at"] = timeProvider.GetUtcNow().AddSeconds(expiresIn).ToString("o");
        auth.Properties.StoreTokens(values.Select(pair => new AuthenticationToken
        {
            Name = pair.Key,
            Value = pair.Value
        }));

        try
        {
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, auth.Principal, auth.Properties);
        }
        catch (InvalidOperationException ex)
        {
            logger.LogDebug(ex, "Could not write rotated tokens to the current response's cookie.");
        }
    }

    private async Task SignOutCurrentSsrCookieIfMutableAsync(string spentRefresh)
    {
        var context = httpContextAccessor.HttpContext;
        if (context is null || context.Response.HasStarted)
            return;

        var auth = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (auth.Properties?.GetTokenValue("refresh_token") != spentRefresh)
            return;

        try
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
        catch (InvalidOperationException ex)
        {
            logger.LogDebug(ex, "Could not sign out the current response after refresh rejection.");
        }
    }

    private void Clear()
    {
        _accessToken = null;
        _refreshToken = null;
        _expiresAt = DateTimeOffset.MaxValue;
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrEmpty(value) ? null : value;
}
