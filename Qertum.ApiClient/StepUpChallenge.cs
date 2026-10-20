using System.Globalization;
using System.Text.RegularExpressions;

namespace Qertum.Services;

/// <summary>
/// What the API asked for in an RFC 9470 step-up challenge (<c>error="insufficient_user_authentication"</c>): the authentication
/// class and the maximum age of the sign-in. Both are nullable because a server may omit them.
/// </summary>
/// <param name="AcrValues">The <c>acr_values</c> to request at the identity provider, or null.</param>
/// <param name="MaxAgeSeconds">The <c>max_age</c> to request, or null.</param>
public sealed partial record StepUpChallenge(string? AcrValues, int? MaxAgeSeconds)
{
    /// <summary>The OAuth error code that marks the challenge.</summary>
    public const string ErrorCode = "insufficient_user_authentication";

    /// <summary>Parses <c>WWW-Authenticate</c> header values; null when none of them is a step-up challenge.</summary>
    /// <param name="wwwAuthenticateValues">The raw header values of a response.</param>
    public static StepUpChallenge? TryParse(IEnumerable<string> wwwAuthenticateValues)
    {
        foreach (var value in wwwAuthenticateValues)
        {
            if (!value.TrimStart().StartsWith("Bearer", StringComparison.OrdinalIgnoreCase))
                continue;

            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match match in ParameterPattern().Matches(value))
                parameters[match.Groups["k"].Value] = match.Groups["v"].Value;

            if (!parameters.TryGetValue("error", out var error) || !string.Equals(error, ErrorCode, StringComparison.Ordinal))
                continue;

            parameters.TryGetValue("acr_values", out var acr);
            int? maxAge = parameters.TryGetValue("max_age", out var age)
                          && int.TryParse(age, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds > 0
                ? seconds
                : null;
            return new StepUpChallenge(string.IsNullOrWhiteSpace(acr) ? null : acr, maxAge);
        }

        return null;
    }

    [GeneratedRegex("(?<k>[A-Za-z_]+)=\"(?<v>[^\"]*)\"")]
    private static partial Regex ParameterPattern();
}
