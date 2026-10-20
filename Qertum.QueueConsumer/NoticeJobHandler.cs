using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Notices;

namespace Qertum.QueueConsumer;

/// <summary>Runs <see cref="WellKnownJobTypes.Notices"/>: one <see cref="NoticeSweeper"/> pass.</summary>
internal sealed class NoticeJobHandler(NoticeSweeper sweeper) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "notices";
    public const string RequestedBy = "notices-scheduler";

    /// <summary>First sweep two minutes after start, then every <c>Notices:CheckIntervalMinutes</c>; off when <c>Notices:Enabled</c> is false.</summary>
    public static IntervalJob Schedule(NoticesOptions options) => new(
        WellKnownJobTypes.Notices, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.FromMinutes(2),
        Interval: TimeSpan.FromMinutes(options.CheckIntervalMinutes),
        Enabled: options.Enabled);

    public string JobType => WellKnownJobTypes.Notices;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken) =>
        (await sweeper.RunAsync(cancellationToken)).ToString();
}
