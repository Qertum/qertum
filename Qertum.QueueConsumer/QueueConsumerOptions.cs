using Qertum.Services.Notices;
namespace Qertum.QueueConsumer;

/// <summary>The <c>QueueConsumer</c> section: the issuance loop's delays.</summary>
public sealed class QueueConsumerOptions
{
    public const string SectionName = "QueueConsumer";

    /// <summary>Wait between polls while nothing is queued. Approvals filed in another process do not
    /// wake this one, so this bounds how long an approved request waits to be signed.</summary>
    public int IdleDelayMs { get; set; } = 10_000;

    /// <summary>Pause after processing a request before looking for the next.</summary>
    public int ProcessingDelayMs { get; set; } = 250;

    /// <summary>Back-off after an unexpected loop error.</summary>
    public int ErrorDelayMs { get; set; } = 2_000;
}

/// <summary>The <c>Webhook</c> section: the delivery outbox poll.</summary>
public sealed class WebhookDeliveryOptions
{
    public const string SectionName = "Webhook";

    public double DeliveryPollIntervalSeconds { get; set; } = 10;
}

/// <summary>The <c>AutoRenewal</c> section: how often certificates near expiry are scanned.</summary>
public sealed class AutoRenewalOptions
{
    public const string SectionName = "AutoRenewal";

    public double CheckIntervalHours { get; set; } = 24;
}

/// <summary>The <c>BackgroundJobs</c> section: the generic job processor's poll, retries and retention.</summary>
public sealed class BackgroundJobOptions
{
    public const string SectionName = "BackgroundJobs";

    /// <summary>Wait between polls while nothing is due; a producer in this process wakes it sooner.</summary>
    public int PollIntervalSeconds { get; set; } = 30;

    /// <summary>Claims before a failing job is marked failed.</summary>
    public int MaxAttempts { get; set; } = 5;

    /// <summary>Delay after the first failed attempt; doubles per attempt.</summary>
    public int RetryBaseDelaySeconds { get; set; } = 30;

    /// <summary>Upper bound on the retry delay.</summary>
    public int MaxRetryDelaySeconds { get; set; } = 3600;

    /// <summary>Completed and failed jobs older than this are deleted.</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>
    /// A job still processing this long after its claim is returned to pending by the hourly
    /// housekeeping pass, so a lost completion cannot hold its concurrency key until restart.
    /// </summary>
    public int ProcessingTimeoutMinutes { get; set; } = 30;
}

/// <summary>The <c>CrlRefresh</c> section: when the scheduler queues a full-CRL refresh.</summary>
public sealed class CrlRefreshOptions
{
    public const string SectionName = "CrlRefresh";

    public bool Enabled { get; set; } = true;

    /// <summary>How often the base CRL's age is checked.</summary>
    public int CheckIntervalMinutes { get; set; } = 15;

    /// <summary>Queue a refresh once the base is older than this fraction of <c>CrlValidityHours</c>.</summary>
    public double RefreshAtFraction { get; set; } = 0.5;
}


public static class QueueConsumerOptionsExtensions
{
    /// <summary>Binds and validates the queue consumer's sections; an invalid value stops the host at startup.</summary>
    public static IServiceCollection AddQueueConsumerOptions(this IServiceCollection services)
    {
        services.AddOptions<QueueConsumerOptions>()
            .BindConfiguration(QueueConsumerOptions.SectionName)
            .Validate(o => o.IdleDelayMs >= 1, "QueueConsumer:IdleDelayMs must be at least 1.")
            .Validate(o => o.ProcessingDelayMs >= 0, "QueueConsumer:ProcessingDelayMs cannot be negative.")
            .Validate(o => o.ErrorDelayMs >= 1, "QueueConsumer:ErrorDelayMs must be at least 1.")
            .ValidateOnStart();
        services.AddOptions<WebhookDeliveryOptions>()
            .BindConfiguration(WebhookDeliveryOptions.SectionName)
            .Validate(o => o.DeliveryPollIntervalSeconds > 0, "Webhook:DeliveryPollIntervalSeconds must be greater than 0.")
            .ValidateOnStart();
        services.AddOptions<AutoRenewalOptions>()
            .BindConfiguration(AutoRenewalOptions.SectionName)
            .Validate(o => o.CheckIntervalHours > 0, "AutoRenewal:CheckIntervalHours must be greater than 0.")
            .ValidateOnStart();
        services.AddOptions<BackgroundJobOptions>()
            .BindConfiguration(BackgroundJobOptions.SectionName)
            .Validate(o => o.PollIntervalSeconds is >= 1 and <= 3600, "BackgroundJobs:PollIntervalSeconds must be between 1 and 3600.")
            .Validate(o => o.MaxAttempts is >= 1 and <= 100, "BackgroundJobs:MaxAttempts must be between 1 and 100.")
            .Validate(o => o.RetryBaseDelaySeconds is >= 1 and <= 3600, "BackgroundJobs:RetryBaseDelaySeconds must be between 1 and 3600.")
            .Validate(o => o.MaxRetryDelaySeconds >= o.RetryBaseDelaySeconds && o.MaxRetryDelaySeconds <= 86_400,
                "BackgroundJobs:MaxRetryDelaySeconds must be at least RetryBaseDelaySeconds and at most 86400.")
            .Validate(o => o.RetentionDays is >= 1 and <= 3650, "BackgroundJobs:RetentionDays must be between 1 and 3650.")
            .Validate(o => o.ProcessingTimeoutMinutes is >= 1 and <= 1440, "BackgroundJobs:ProcessingTimeoutMinutes must be between 1 and 1440.")
            .ValidateOnStart();
        services.AddOptions<CrlRefreshOptions>()
            .BindConfiguration(CrlRefreshOptions.SectionName)
            .Validate(o => o.CheckIntervalMinutes is >= 1 and <= 1440, "CrlRefresh:CheckIntervalMinutes must be between 1 and 1440.")
            .Validate(o => o.RefreshAtFraction is > 0 and < 1, "CrlRefresh:RefreshAtFraction must be greater than 0 and less than 1.")
            .ValidateOnStart();
        services.AddOptions<NoticesOptions>()
            .BindConfiguration(NoticesOptions.SectionName)
            .Validate(o => o.CheckIntervalMinutes is >= 1 and <= 1440, "Notices:CheckIntervalMinutes must be between 1 and 1440.")
            .Validate(o => NoticeRules.ExpiryDaysProblem(o.ExpiryDays) is null,
                "Notices:ExpiryDays must list 1 to 10 distinct whole numbers between 1 and 3650, separated by commas.")
            .Validate(o => o.EscalationAfterHours is >= 1 and <= 720, "Notices:EscalationAfterHours must be between 1 and 720.")
            .Validate(o => o.RetentionDays is >= 1 and <= 3650, "Notices:RetentionDays must be between 1 and 3650.")
            .ValidateOnStart();

        services.AddOptions<Qertum.Services.AuditLogOptions>()
            .BindConfiguration(Qertum.Services.AuditLogOptions.SectionName)
            .Validate(o => o.Checkpoint.IntervalMinutes is >= 1 and <= 1440, "AuditLog:Checkpoint:IntervalMinutes must be between 1 and 1440.")
            .ValidateOnStart();
        services.AddOptions<AcmeExpiryCleanupOptions>()
            .BindConfiguration(AcmeExpiryCleanupOptions.SectionName)
            .Validate(o => o.Interval >= TimeSpan.FromMinutes(1), "Acme:ExpiryCleanup:Interval must be at least 00:01:00.")
            .Validate(o => o.Retention >= TimeSpan.Zero, "Acme:ExpiryCleanup:Retention cannot be negative.")
            .Validate(o => o.BatchSize is >= 1 and <= 10_000, "Acme:ExpiryCleanup:BatchSize must be between 1 and 10000.")
            .ValidateOnStart();

        return services;
    }
}
