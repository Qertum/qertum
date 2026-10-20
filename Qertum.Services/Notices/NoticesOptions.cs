namespace Qertum.Services.Notices;

/// <summary>The <c>Notices</c> section: when expiry and renewal notices are checked and how long they are kept.</summary>
public sealed class NoticesOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Notices";

    /// <summary>Whether the sweeper runs at all.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often the sweeper runs, 1 to 1440 minutes.</summary>
    public int CheckIntervalMinutes { get; set; } = 60;

    /// <summary>
    /// Days before expiry at which an <see cref="NoticeKind.Expiring"/> notice is raised: a comma-separated list of
    /// 1 to 10 distinct whole numbers of 1 to 3650, for example <c>30,14,7,1</c>. A string rather than an array because
    /// the configuration binder appends to a non-empty default array instead of replacing it.
    /// </summary>
    public string ExpiryDays { get; set; } = "30,14,7,1";

    /// <summary>The whole numbers in <see cref="ExpiryDays"/>; anything that is not a whole number is skipped (validation rejects it).</summary>
    public IReadOnlyList<int> ExpiryDayList => NoticeRules.ParseExpiryDays(ExpiryDays);

    /// <summary>How long a stalled or failed renewal stays unresolved before the notice repeats at level 2, 1 to 720 hours.</summary>
    public int EscalationAfterHours { get; set; } = 24;

    /// <summary>Resolved notices older than this are deleted, 1 to 3650 days.</summary>
    public int RetentionDays { get; set; } = 90;
}
