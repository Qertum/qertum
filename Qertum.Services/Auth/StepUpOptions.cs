namespace Qertum.Services.Auth;

/// <summary>
/// Step-up settings (<c>Identity:StepUp</c>). When enabled, the sensitive operations in <see cref="StepUpRoutes"/> need an
/// access token whose <c>acr</c> is one of <see cref="AcceptedAcrValues"/> and whose <c>auth_time</c> is recent. The identity
/// provider must be configured to emit both claims; Qertum reads nothing else.
/// </summary>
public sealed class StepUpOptions
{
    /// <summary>The largest <see cref="MaxAgeSeconds"/>: one day.</summary>
    public const int MaxAgeSecondsLimit = 86_400;

    /// <summary>Whether protected operations require step-up. Default: false.</summary>
    public bool Enabled { get; set; }

    /// <summary>Comma-separated <c>acr</c> values that mean "second factor done". Default: <c>mfa</c>. Compared case-sensitively.</summary>
    public string AcrValues { get; set; } = "mfa";

    /// <summary>How old <c>auth_time</c> may be, in seconds, 1 to 86400. Default: 300.</summary>
    public int MaxAgeSeconds { get; set; } = 300;

    /// <summary>Name of the authentication-class claim. Default: <c>acr</c>.</summary>
    public string AcrClaimType { get; set; } = "acr";

    /// <summary>Name of the last-authentication-time claim (Unix seconds). Default: <c>auth_time</c>.</summary>
    public string AuthTimeClaimType { get; set; } = "auth_time";

    /// <summary><see cref="AcrValues"/> split, trimmed and de-duplicated.</summary>
    public IReadOnlyList<string> AcceptedAcrValues =>
        AcrValues.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal).ToList();

    /// <summary>Throws <see cref="InvalidOperationException"/> naming the key when a setting is unusable.</summary>
    public void Validate()
    {
        if (MaxAgeSeconds is < 1 or > MaxAgeSecondsLimit)
            throw new InvalidOperationException($"Identity:StepUp:MaxAgeSeconds must be between 1 and {MaxAgeSecondsLimit}.");
        if (string.IsNullOrWhiteSpace(AcrClaimType))
            throw new InvalidOperationException("Identity:StepUp:AcrClaimType must not be empty.");
        if (string.IsNullOrWhiteSpace(AuthTimeClaimType))
            throw new InvalidOperationException("Identity:StepUp:AuthTimeClaimType must not be empty.");
        if (Enabled && AcceptedAcrValues.Count == 0)
            throw new InvalidOperationException("Identity:StepUp:AcrValues must list at least one value when step-up is enabled.");
        if (AcceptedAcrValues.Any(v => v.Any(c => c is '"' or '\\' || char.IsWhiteSpace(c) || char.IsControl(c))))
            throw new InvalidOperationException("Identity:StepUp:AcrValues must not contain quotes, backslashes, spaces or control characters.");
    }
}
