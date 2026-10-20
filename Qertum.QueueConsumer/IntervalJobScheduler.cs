using System.Globalization;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.QueueConsumer;

/// <summary>
/// A job queued on a fixed timer. <see cref="ConcurrencyKey"/> keeps at most one run pending or
/// processing, so a slow or retrying run absorbs the next tick instead of piling up.
/// </summary>
internal sealed record IntervalJob(
    string JobType,
    string ConcurrencyKey,
    string RequestedBy,
    TimeSpan InitialDelay,
    TimeSpan Interval,
    bool Enabled = true,
    Func<IServiceProvider, CancellationToken, Task<bool>>? IsWanted = null)
{
    public string Reason => string.Create(CultureInfo.InvariantCulture, $"scheduled every {Interval}");
}

/// <summary>
/// Producer only: after <see cref="IntervalJob.InitialDelay"/>, queues <see cref="IntervalJob.JobType"/>
/// every <see cref="IntervalJob.Interval"/>. Never runs the work itself; <see cref="BackgroundJobProcessor"/> does,
/// so each run is recorded as a background job with its diagnostic events.
/// </summary>
internal sealed class IntervalJobScheduler(
    IntervalJob schedule,
    IServiceScopeFactory scopeFactory,
    IBackgroundJobSignal signal,
    ILogger<IntervalJobScheduler> logger,
    TimeProvider clock) : BackgroundService
{
    public IntervalJob Schedule => schedule;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!schedule.Enabled)
        {
            logger.LogInformation("Scheduled {JobType} is disabled.", schedule.JobType);
            return;
        }

        try { await Task.Delay(schedule.InitialDelay, clock, stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await EnqueueOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Queueing scheduled {JobType} failed; will retry in {Interval}.",
                    schedule.JobType, schedule.Interval);
            }

            try { await Task.Delay(schedule.Interval, clock, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>Queues one run unless unwanted or one is already active. Returns the queued job, or null.</summary>
    internal async Task<BackgroundJob?> EnqueueOnceAsync(CancellationToken cancellationToken)
    {
        if (!schedule.Enabled) return null;

        await using var scope = scopeFactory.CreateAsyncScope();
        if (schedule.IsWanted is { } isWanted && !await isWanted(scope.ServiceProvider, cancellationToken))
            return null;

        var job = await scope.ServiceProvider.GetRequiredService<IBackgroundJobQueue>().EnqueueAsync(
            schedule.JobType, schedule.ConcurrencyKey, schedule.RequestedBy, schedule.Reason,
            cancellationToken: cancellationToken);
        if (job is not null)
            signal.TrySignal();
        return job;
    }
}
