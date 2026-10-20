using System.CommandLine;

namespace Qertum.Cli.Auth;

internal static class SessionResolver
{
    /// <summary>
    /// Resolves the effective bearer token and service URLs for a command invocation.
    /// Priority: --token/QERTUM_TOKEN (explicit) → cached session (with auto-refresh).
    /// When the cached token is expired and cannot be refreshed, the session is cleared
    /// and null is returned after printing an error.
    /// </summary>
    public static async Task<ResolvedSession?> ResolveAsync(
        ParseResult result,
        Option<string?> tokenOption,
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        CancellationToken ct = default)
    {
        var explicitToken = result.GetValue(tokenOption)
            ?? Environment.GetEnvironmentVariable("QERTUM_TOKEN");

        var explicitApiUrl = result.GetValue(apiUrlOption)
            ?? Environment.GetEnvironmentVariable("QERTUM_API_URL");

        var explicitIdentityUrl = result.GetValue(identityUrlOption)
            ?? Environment.GetEnvironmentVariable("QERTUM_IDENTITY_URL");

        if (explicitToken is not null)
        {
            var cached = TokenCache.Load();
            return new ResolvedSession(
                explicitToken,
                explicitApiUrl ?? cached?.ApiUrl ?? string.Empty);
        }

        var session = TokenCache.Load();
        if (session is null)
        {
            await Console.Error.WriteLineAsync("error: not logged in. Run 'qertum auth login'.");
            return null;
        }

        if (!string.IsNullOrEmpty(explicitApiUrl)) session.ApiUrl = explicitApiUrl;
        if (!string.IsNullOrEmpty(explicitIdentityUrl)) session.IdentityUrl = explicitIdentityUrl;

        if (session.IsExpired)
        {
            if (!string.IsNullOrEmpty(session.RefreshToken))
            {
                try
                {
                    session = await OidcLogin.RefreshAsync(session, ct);
                    TokenCache.Save(session);
                }
                catch
                {
                    TokenCache.Clear();
                    await Console.Error.WriteLineAsync("error: session expired. Run 'qertum auth login'.");
                    return null;
                }
            }
            else
            {
                TokenCache.Clear();
                await Console.Error.WriteLineAsync("error: session expired. Run 'qertum auth login'.");
                return null;
            }
        }
        else if (session.IsExpiringSoon && !string.IsNullOrEmpty(session.RefreshToken))
        {
            try
            {
                session = await OidcLogin.RefreshAsync(session, ct);
                TokenCache.Save(session);
            }
            catch
            {
                // Token still valid for a few minutes — continue with current
            }
        }

        return new ResolvedSession(session.AccessToken, session.ApiUrl);
    }
}

internal sealed record ResolvedSession(
    string Token,
    string ApiUrl);
