using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Qertum.Services;

namespace Qertum.Web.Auth;

/// <summary>The pieces of the step-up round trip: the URL the layout navigates to, the checks on its input, and the OIDC parameters.</summary>
public static partial class StepUpRedirect
{
    /// <summary>Authentication-properties item carrying the requested <c>acr_values</c>.</summary>
    public const string AcrItem = "qertum.acr_values";

    /// <summary>Authentication-properties item carrying the requested <c>max_age</c>.</summary>
    public const string MaxAgeItem = "qertum.max_age";

    /// <summary>Query parameter that marks a page the user has just come back to from a step-up, with the Unix time of the return.</summary>
    public const string MarkerParameter = "qertum_stepup";

    private static readonly TimeSpan MarkerWindow = TimeSpan.FromSeconds(60);

    /// <summary>Appends the step-up marker to <paramref name="returnUrl"/>, so a challenge that fires again right after can be told from a new one.</summary>
    public static string WithMarker(string returnUrl, DateTimeOffset now) =>
        $"{returnUrl}{(returnUrl.Contains('?') ? '&' : '?')}{MarkerParameter}={now.ToUnixTimeSeconds()}";

    /// <summary>
    /// True when <paramref name="url"/> carries a marker set at most a minute ago: the identity provider has just failed to
    /// satisfy the challenge, and redirecting again would only loop. A missing, malformed or future-dated marker is false.
    /// </summary>
    public static bool CameBackRecently(string url, DateTimeOffset now)
    {
        var query = url.IndexOf('?') is var q and >= 0 ? url[q..] : string.Empty;
        var values = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(query);
        if (!values.TryGetValue(MarkerParameter, out var raw)
            || !long.TryParse(raw.ToString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var seconds)
            || seconds > 253_402_300_799)
            return false;

        var age = now - DateTimeOffset.FromUnixTimeSeconds(seconds);
        return age >= TimeSpan.Zero && age <= MarkerWindow;
    }

    /// <summary>The <c>/auth/step-up</c> URL that re-authenticates the user and returns to <paramref name="returnUrl"/>.</summary>
    public static string BuildUrl(string returnUrl, StepUpChallenge challenge)
    {
        var url = "/auth/step-up?returnUrl=" + Uri.EscapeDataString(returnUrl);
        if (!string.IsNullOrWhiteSpace(challenge.AcrValues))
            url += "&acr_values=" + Uri.EscapeDataString(challenge.AcrValues);
        if (challenge.MaxAgeSeconds is > 0)
            url += "&max_age=" + challenge.MaxAgeSeconds.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return url;
    }

    /// <summary>True for a local absolute path only: never another host, never a protocol-relative or backslash form.</summary>
    public static bool IsSafeReturnUrl(string? url) =>
        !string.IsNullOrEmpty(url) && url[0] == '/' && !url.StartsWith("//", StringComparison.Ordinal)
        && !url.StartsWith("/\\", StringComparison.Ordinal) && url.All(c => !char.IsControl(c));

    /// <summary>True for space-separated tokens made of letters, digits, <c>:</c>, <c>.</c>, <c>_</c> and <c>-</c>.</summary>
    public static bool IsAcceptableAcrValues(string? value) => !string.IsNullOrEmpty(value) && AcrPattern().IsMatch(value);

    /// <summary>True for 1 to 86400 seconds.</summary>
    public static bool IsAcceptableMaxAge(int? value) => value is >= 1 and <= 86_400;

    /// <summary>Copies the requested step-up parameters from the challenge's properties onto the authorization request.</summary>
    public static void Apply(RedirectContext context)
    {
        if (context.Properties.Items.TryGetValue(AcrItem, out var acr) && IsAcceptableAcrValues(acr))
            context.ProtocolMessage.AcrValues = acr;
        if (context.Properties.Items.TryGetValue(MaxAgeItem, out var age)
            && int.TryParse(age, out var seconds) && IsAcceptableMaxAge(seconds))
            context.ProtocolMessage.MaxAge = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [GeneratedRegex(@"^[A-Za-z0-9:._\-]+( [A-Za-z0-9:._\-]+)*$")]
    private static partial Regex AcrPattern();
}
