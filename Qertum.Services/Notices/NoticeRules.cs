namespace Qertum.Services.Notices;

/// <summary>The pure decisions behind notices: which threshold, how many days, when to escalate.</summary>
public static class NoticeRules
{
    /// <summary>
    /// How long past its expiry an open <see cref="NoticeKind.Expiring"/> notice is kept before it resolves, so a
    /// decommissioned certificate that was never renewed does not keep a notice open forever.
    /// </summary>
    public const int ExpiredGraceDays = 7;

    /// <summary>
    /// The most urgent threshold the certificate is inside, or null when it is outside all of them or already expired.
    /// After downtime several thresholds may have been crossed; only the smallest is returned.
    /// </summary>
    public static int? ExpiryStep(DateTime validToUtc, DateTime nowUtc, IReadOnlyList<int> thresholdDays)
    {
        if (validToUtc <= nowUtc) return null;
        var left = validToUtc - nowUtc;
        int? best = null;
        foreach (var threshold in thresholdDays)
        {
            if (left <= TimeSpan.FromDays(threshold) && (best is null || threshold < best))
                best = threshold;
        }
        return best;
    }

    /// <summary>Whole days left, rounded up, for the payload and the wording.</summary>
    public static int DaysLeft(DateTime validToUtc, DateTime nowUtc) =>
        (int)Math.Ceiling((validToUtc - nowUtc).TotalDays);

    /// <summary>True once the certificate has been expired for more than <see cref="ExpiredGraceDays"/>.</summary>
    public static bool ExpiredPastGrace(DateTime validToUtc, DateTime nowUtc) =>
        validToUtc.AddDays(ExpiredGraceDays) < nowUtc;

    /// <summary>True once a notice raised at <paramref name="raisedAtUtc"/> is old enough to repeat at the next level.</summary>
    public static bool EscalationDue(DateTime raisedAtUtc, DateTime nowUtc, int escalationAfterHours) =>
        nowUtc - raisedAtUtc >= TimeSpan.FromHours(escalationAfterHours);

    /// <summary>The whole numbers in a comma-separated list; entries that are not whole numbers are skipped.</summary>
    public static IReadOnlyList<int> ParseExpiryDays(string text) =>
        [.. (text ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(t => int.TryParse(t, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out _))
            .Select(t => int.Parse(t, System.Globalization.CultureInfo.InvariantCulture))];

    /// <summary>Why <paramref name="text"/> is not a valid <c>Notices:ExpiryDays</c> list, or null when it is.</summary>
    public static string? ExpiryDaysProblem(string text)
    {
        var tokens = (text ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var days = ParseExpiryDays(text ?? string.Empty);
        if (tokens.Length < 1 || tokens.Length > 10)
            return "Notices:ExpiryDays must list between 1 and 10 values.";
        if (days.Count != tokens.Length)
            return "Notices:ExpiryDays values must be whole numbers.";
        if (days.Any(d => d is < 1 or > 3650))
            return "Notices:ExpiryDays values must be between 1 and 3650.";
        if (days.Distinct().Count() != days.Count)
            return "Notices:ExpiryDays values must be distinct.";
        return null;
    }

    /// <summary>The first problem with <paramref name="options"/>, or null when it is valid.</summary>
    public static string? Check(NoticesOptions options)
    {
        if (options.CheckIntervalMinutes is < 1 or > 1440)
            return "Notices:CheckIntervalMinutes must be between 1 and 1440.";
        if (ExpiryDaysProblem(options.ExpiryDays) is { } problem)
            return problem;
        if (options.EscalationAfterHours is < 1 or > 720)
            return "Notices:EscalationAfterHours must be between 1 and 720.";
        if (options.RetentionDays is < 1 or > 3650)
            return "Notices:RetentionDays must be between 1 and 3650.";
        return null;
    }
}
