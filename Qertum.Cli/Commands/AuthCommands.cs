using System.CommandLine;
using System.Text.Json;
using Qertum.Cli.Auth;

namespace Qertum.Cli.Commands;

internal static class AuthCommands
{
    private static readonly JsonSerializerOptions JsonPrint = new() { WriteIndented = true };

    private const string LoginHelp =
        "Sign in with the OAuth device authorization flow and save the session.\n\n" +
        "Starts the device flow against the identity service and shows a code to confirm in a browser. Creates (or replaces) the saved session in the CLI cache, which later commands use and refresh automatically. " +
        "The identity and API URLs come from --identity-url / --api-url, then QERTUM_IDENTITY_URL / QERTUM_API_URL, then the previously saved session; both must be found or login fails. A refused sensitive operation prints the exact --acr-values and --max-age to use here.\n" +
        "Needs: nothing (no sign-in required).\n" +
        "Exit codes: 0 logged in; 1 a URL is missing, the login was cancelled, or it failed.\n" +
        "Output: text only (user name and session expiry); --output json has no effect.\n" +
        "Example: qca auth login --identity-url https://identity.example.com --api-url https://api.example.com";

    private const string LogoutHelp =
        "Sign out: revoke the saved refresh token and clear the saved session.\n\n" +
        "Asks the identity service to revoke the refresh token (best effort: a failure there is ignored), then deletes the saved session from this machine. Revokes the refresh token and clears credentials; an access token already issued stays valid until it expires. " +
        "With no saved session it prints that and changes nothing.\n" +
        "Needs: nothing (no sign-in required).\n" +
        "Exit codes: 0 always (including when there was no session).\n" +
        "Output: text only; --output json has no effect.\n" +
        "Example: qca auth logout";

    private const string StatusHelp =
        "Show who the CLI is signed in as and when the session expires.\n\n" +
        "Reads only local state and never contacts the server. With --token (or QERTUM_TOKEN) it describes that token (mode explicit: user, roles, expiry, valid or expired); otherwise it describes the saved session (mode cached, status valid, expiring_soon or expired).\n" +
        "Needs: nothing (no sign-in required).\n" +
        "Exit codes: 0 a token or session was described (even if expired); 1 there is no saved session and no --token.\n" +
        "Output: --output json prints an object with mode, username, roles, expiresAt and status (a cached session adds loggedIn, apiUrl, identityUrl and cacheFile); with no session it prints {\"loggedIn\": false}.\n" +
        "Example: qca auth status --output json";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var authCommand = new Command("auth", "Authentication commands");

        authCommand.Subcommands.Add(BuildLogin(apiUrlOption, identityUrlOption));
        authCommand.Subcommands.Add(BuildLogout());
        authCommand.Subcommands.Add(BuildStatus(tokenOption, outputOption));

        return authCommand;
    }

    private static Command BuildLogin(Option<string?> apiUrlOption, Option<string?> identityUrlOption)
    {
        var cmd = new Command("login", LoginHelp);
        var acrOption = new Option<string?>("--acr-values")
        {
            Description = "Ask the identity provider for this authentication class (for example mfa), as printed by a refused operation. Whether the device flow honours it depends on the provider."
        };
        var maxAgeOption = new Option<int?>("--max-age")
        {
            Description = "Ask the identity provider to re-authenticate if your sign-in is older than this many seconds (1 to 86400)."
        };
        cmd.Options.Add(acrOption);
        cmd.Options.Add(maxAgeOption);

        cmd.SetAction(async (result, ct) =>
        {
            var identityUrl = result.GetValue(identityUrlOption)
                ?? Environment.GetEnvironmentVariable("QERTUM_IDENTITY_URL")
                ?? TokenCache.Load()?.IdentityUrl;

            var apiUrl = result.GetValue(apiUrlOption)
                ?? Environment.GetEnvironmentVariable("QERTUM_API_URL")
                ?? TokenCache.Load()?.ApiUrl;

            if (string.IsNullOrWhiteSpace(identityUrl))
            {
                await Console.Error.WriteLineAsync(
                    "error: identity service URL required.\n" +
                    "  Pass --identity-url <url>, or set QERTUM_IDENTITY_URL.");
                return 1;
            }

            if (string.IsNullOrWhiteSpace(apiUrl))
            {
                await Console.Error.WriteLineAsync(
                    "error: API service URL required.\n" +
                    "  Pass --api-url <url>, or set QERTUM_API_URL.");
                return 1;
            }

            try
            {
                var acr = result.GetValue(acrOption);
                var maxAge = result.GetValue(maxAgeOption);
                if (maxAge is < 1 or > 86_400)
                {
                    await Console.Error.WriteLineAsync("error: --max-age must be between 1 and 86400.");
                    return 1;
                }

                var session = await OidcLogin.LoginAsync(identityUrl, apiUrl, acr, maxAge, ct);
                TokenCache.Save(session);
                Console.WriteLine($"Logged in as {session.Username}");
                Console.WriteLine($"Session expires: {session.ExpiresAt.ToLocalTime():g}");
                return 0;
            }
            catch (OperationCanceledException)
            {
                await Console.Error.WriteLineAsync("Login cancelled.");
                return 1;
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"error: {ex.Message}");
                return 1;
            }
        });

        return cmd;
    }

    private static Command BuildLogout()
    {
        var cmd = new Command("logout", LogoutHelp);

        cmd.SetAction(async (_, ct) =>
        {
            var session = TokenCache.Load();
            if (session is null)
            {
                Console.WriteLine("No active session found.");
                return 0;
            }

            await OidcLogin.RevokeAsync(session, ct);
            TokenCache.Clear();
            Console.WriteLine($"Logged out {session.Username}. Session cleared.");
            return 0;
        });

        return cmd;
    }

    private static Command BuildStatus(Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("status", StatusHelp);

        cmd.SetAction(result =>
        {
            var format = result.GetValue(outputOption);
            var explicitToken = result.GetValue(tokenOption)
                ?? Environment.GetEnvironmentVariable("QERTUM_TOKEN");

            if (explicitToken is not null)
            {
                var expiry = JwtPayload.ExtractExpiry(explicitToken);
                var username = JwtPayload.ExtractUsername(explicitToken);
                var roles = JwtPayload.ExtractRoles(explicitToken).ToList();
                var expired = expiry.HasValue && expiry.Value < TimeProvider.System.GetUtcNow();

                if (format == "json")
                {
                    Console.WriteLine(JsonSerializer.Serialize(new
                    {
                        mode = "explicit",
                        username,
                        roles,
                        expiresAt = expiry?.ToString("o"),
                        status = expired ? "expired" : "valid"
                    }, JsonPrint));
                    return 0;
                }

                Console.WriteLine("Mode:    explicit --token");
                Console.WriteLine($"User:    {username}");
                Console.WriteLine($"Roles:   {(roles.Count > 0 ? string.Join(", ", roles) : "(none)")}");
                Console.WriteLine($"Expires: {(expiry.HasValue ? expiry.Value.ToLocalTime().ToString("g") : "unknown")}");
                Console.WriteLine($"Status:  {(expired ? "EXPIRED" : "valid")}");
                return 0;
            }

            var session = TokenCache.Load();
            if (session is null)
            {
                Console.WriteLine(format == "json"
                    ? JsonSerializer.Serialize(new { loggedIn = false }, JsonPrint)
                    : "Not logged in. Run 'qertum auth login' to authenticate.");
                return 1;
            }

            var tokenRoles = JwtPayload.ExtractRoles(session.AccessToken).ToList();
            var statusText = session.IsExpired ? "expired"
                : session.IsExpiringSoon ? "expiring_soon"
                : "valid";

            if (format == "json")
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    mode = "cached",
                    loggedIn = true,
                    username = session.Username,
                    roles = tokenRoles,
                    apiUrl = session.ApiUrl,
                    identityUrl = session.IdentityUrl,
                    expiresAt = session.ExpiresAt.ToString("o"),
                    status = statusText,
                    cacheFile = TokenCache.CacheFilePath
                }, JsonPrint));
                return 0;
            }

            Console.WriteLine("Mode:        cached session");
            Console.WriteLine($"User:        {session.Username}");
            Console.WriteLine($"Roles:       {(tokenRoles.Count > 0 ? string.Join(", ", tokenRoles) : "(none)")}");
            Console.WriteLine($"API URL:     {session.ApiUrl}");
            Console.WriteLine($"Identity:    {session.IdentityUrl}");
            Console.WriteLine($"Expires:     {session.ExpiresAt.ToLocalTime():g}");
            Console.WriteLine($"Cache file:  {TokenCache.CacheFilePath}");
            Console.WriteLine($"Status:      {(session.IsExpired ? "EXPIRED — run 'qertum auth login'" : session.IsExpiringSoon ? "expiring soon" : "valid")}");
            return 0;
        });

        return cmd;
    }
}
