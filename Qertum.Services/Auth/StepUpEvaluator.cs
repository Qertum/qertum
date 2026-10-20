using System.Globalization;
using System.Security.Claims;

namespace Qertum.Services.Auth;

/// <summary>Why a token does or does not satisfy step-up.</summary>
public enum StepUpResult
{
    /// <summary>Step-up is disabled, or the token carries a listed <c>acr</c> and a recent <c>auth_time</c>.</summary>
    Satisfied,

    /// <summary>The token has no <c>acr</c> claim.</summary>
    NoAcr,

    /// <summary>No <c>acr</c> value is one of the accepted ones.</summary>
    WrongAcr,

    /// <summary>The token has no <c>auth_time</c> claim.</summary>
    NoAuthTime,

    /// <summary><c>auth_time</c> is not a whole, plausible Unix timestamp.</summary>
    BadAuthTime,

    /// <summary><c>auth_time</c> is more than 30 seconds in the future.</summary>
    AuthTimeInFuture,

    /// <summary><c>auth_time</c> is older than <see cref="StepUpOptions.MaxAgeSeconds"/>.</summary>
    Stale
}

/// <summary>Decides from the validated token's claims, and the clock, whether the caller recently did a second factor.</summary>
public sealed class StepUpEvaluator(StepUpOptions options, TimeProvider clock)
{
    private static readonly TimeSpan FutureTolerance = TimeSpan.FromSeconds(30);

    /// <summary>The settings this evaluator applies.</summary>
    public StepUpOptions Options { get; } = options;

    /// <summary>Evaluates <paramref name="user"/>. Always <see cref="StepUpResult.Satisfied"/> when step-up is disabled.</summary>
    public StepUpResult Evaluate(ClaimsPrincipal user)
    {
        if (!Options.Enabled)
            return StepUpResult.Satisfied;

        var acrs = user.FindAll(Options.AcrClaimType).Select(c => c.Value).ToList();
        if (acrs.Count == 0)
            return StepUpResult.NoAcr;
        var accepted = Options.AcceptedAcrValues;
        if (!acrs.Any(a => accepted.Contains(a, StringComparer.Ordinal)))
            return StepUpResult.WrongAcr;

        var raw = user.FindFirst(Options.AuthTimeClaimType)?.Value;
        if (raw is null)
            return StepUpResult.NoAuthTime;
        if (!long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) || seconds > 253_402_300_799)
            return StepUpResult.BadAuthTime;

        var age = clock.GetUtcNow() - DateTimeOffset.FromUnixTimeSeconds(seconds);
        if (age < -FutureTolerance)
            return StepUpResult.AuthTimeInFuture;
        return age > TimeSpan.FromSeconds(Options.MaxAgeSeconds) ? StepUpResult.Stale : StepUpResult.Satisfied;
    }

    /// <summary>A fixed sentence for the problem body. Never contains a claim value.</summary>
    public static string Describe(StepUpResult result) => result switch
    {
        StepUpResult.NoAcr => "The access token has no authentication class (acr) claim.",
        StepUpResult.WrongAcr => "The access token's authentication class is not one this server accepts for this operation.",
        StepUpResult.NoAuthTime => "The access token has no authentication time (auth_time) claim.",
        StepUpResult.BadAuthTime => "The access token's authentication time (auth_time) is not a valid Unix timestamp.",
        StepUpResult.AuthTimeInFuture => "The access token's authentication time (auth_time) is in the future.",
        StepUpResult.Stale => "The last sign-in is too old for this operation.",
        _ => string.Empty
    };
}
