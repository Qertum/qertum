using Qertum.Cli.Auth;

namespace Qertum.Cli.Doctor;

/// <summary>URLs and token given by the user (option or environment, already combined by the caller).</summary>
internal sealed record DoctorInputs(string? ApiUrl, string? IdentityUrl, string? Token);

/// <summary>
/// Builds the context from the explicit inputs and the cached session. It is given a loader and nothing
/// else for the cache, so it cannot write, refresh or clear it (unlike <c>SessionResolver</c>, which
/// prints errors and clears the cache when a refresh fails). An expired token is reported, not renewed.
/// </summary>
internal static class DoctorContextFactory
{
    public static DoctorContext Create(
        DoctorInputs inputs, Func<CachedSession?> loadSession, HttpMessageHandler handler,
        TimeProvider clock, IRootStore rootStore, TimeSpan timeout)
    {
        var cached = loadSession();
        string? token = null;
        string? problem = null;
        DateTimeOffset? expiresAt = null;

        if (!string.IsNullOrWhiteSpace(inputs.Token))
        {
            token = inputs.Token;
            expiresAt = JwtPayload.ExtractExpiry(token);
        }
        else if (cached is not null && !string.IsNullOrEmpty(cached.AccessToken))
        {
            token = cached.AccessToken;
            expiresAt = cached.ExpiresAt;
        }
        else
        {
            problem = "not logged in: run 'qca auth login' or pass --token";
        }

        if (token is not null && expiresAt is { } expiry && clock.GetUtcNow() >= expiry)
        {
            problem = $"the token expired at {expiry:yyyy-MM-dd HH:mm} UTC: run 'qca auth login'";
            token = null;
        }

        return new DoctorContext
        {
            ApiUrl = Clean(inputs.ApiUrl) ?? Clean(cached?.ApiUrl),
            IdentityUrl = Clean(inputs.IdentityUrl) ?? Clean(cached?.IdentityUrl),
            Token = token,
            TokenProblem = problem,
            Handler = handler,
            Clock = clock,
            RootStore = rootStore,
            Timeout = timeout
        };
    }

    private static string? Clean(string? url) =>
        string.IsNullOrWhiteSpace(url) ? null : url.Trim().TrimEnd('/');
}
