using Microsoft.Extensions.Options;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Notices;

namespace Qertum.QueueConsumer;

internal static class BackgroundJobRegistration
{
    /// <summary>The background job processor, its handlers and the producers that feed it.</summary>
    public static IServiceCollection AddBackgroundJobs(this IServiceCollection services)
    {
        services.AddScoped<IBackgroundJobHandler, CrlRefreshJobHandler>();
        services.AddScoped<IBackgroundJobHandler, AutoRenewalJobHandler>();
        services.AddScoped<IBackgroundJobHandler, LifecycleEventRetentionJobHandler>();
        services.AddScoped<IBackgroundJobHandler, AcmeExpiryCleanupJobHandler>();
        services.AddScoped<IBackgroundJobHandler, BulkOperationJobHandler>();
        services.AddScoped<IBackgroundJobHandler, BulkOperationRetentionJobHandler>();
        services.AddScoped<Qertum.Services.Approvals.ApprovalSweeper>();
        services.AddScoped<IBackgroundJobHandler, ApprovalRetentionJobHandler>();
        services.AddScoped<NoticeSweeper>();
        services.AddScoped<IBackgroundJobHandler, NoticeJobHandler>();
        services.AddScoped<IBackgroundJobHandler, AuditCheckpointJobHandler>();
        services.AddHostedService<BackgroundJobProcessor>();
        services.AddHostedService<CrlRefreshScheduler>();
        services.AddIntervalJob(sp => AutoRenewalJobHandler.Schedule(sp.GetRequiredService<IOptions<AutoRenewalOptions>>().Value));
        services.AddIntervalJob(_ => LifecycleEventRetentionJobHandler.Schedule);
        services.AddIntervalJob(sp => AcmeExpiryCleanupJobHandler.Schedule(sp.GetRequiredService<IOptions<AcmeExpiryCleanupOptions>>().Value));
        services.AddIntervalJob(_ => BulkOperationRetentionJobHandler.Schedule);
        services.AddIntervalJob(_ => ApprovalRetentionJobHandler.Schedule);
        services.AddIntervalJob(sp => NoticeJobHandler.Schedule(sp.GetRequiredService<IOptions<NoticesOptions>>().Value));
        services.AddIntervalJob(sp => AuditCheckpointJobHandler.Schedule(sp.GetRequiredService<IOptions<Qertum.Services.AuditLogOptions>>().Value.Checkpoint));
        return services;
    }

    // AddHostedService deduplicates by implementation type, so each schedule is its own IHostedService registration.
    private static void AddIntervalJob(this IServiceCollection services, Func<IServiceProvider, IntervalJob> schedule) =>
        services.AddSingleton<IHostedService>(sp => ActivatorUtilities.CreateInstance<IntervalJobScheduler>(sp, schedule(sp)));
}
