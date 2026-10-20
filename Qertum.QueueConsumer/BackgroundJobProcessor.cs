using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.QueueConsumer;

/// <summary>
/// The generic consumer of the <c>BackgroundJobs</c> queue: claims due jobs of the types it has
/// handlers for, runs them, and records completion, retry or failure through the queue.
/// </summary>
internal sealed class BackgroundJobProcessor(
    IServiceScopeFactory scopeFactory,
    IBackgroundJobSignal signal,
    IOptions<BackgroundJobOptions> options,
    ILogger<BackgroundJobProcessor> logger,
    TimeProvider clock,
    OperationsMetrics? metrics = null) : BackgroundService
{
    private static readonly TimeSpan HousekeepingInterval = TimeSpan.FromHours(1);
    private readonly BackgroundJobOptions _options = options.Value;
    private DateTimeOffset? _lastHousekeeping;

    internal static TimeSpan RetryDelay(int attempt, BackgroundJobOptions options)
    {
        var seconds = options.RetryBaseDelaySeconds * Math.Pow(2, Math.Max(0, attempt - 1));
        return TimeSpan.FromSeconds(Math.Min(seconds, options.MaxRetryDelaySeconds));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await using (var scope = scopeFactory.CreateAsyncScope())
        {
            // Fails the host at startup when two handlers claim one job type — deliberately unguarded.
            var handlers = BackgroundJobHandlers.Map(scope.ServiceProvider.GetServices<IBackgroundJobHandler>());
            logger.LogInformation("Background job processor started for job types: {JobTypes}.", string.Join(", ", handlers.Keys));
        }
        await RecoverAtStartupAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            var processed = false;
            try
            {
                await HousekeepingIfDueAsync(stoppingToken);
                processed = await RunOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Never let one bad iteration stop the host (BackgroundService default is StopHost).
                logger.LogError(ex, "Background job processor iteration failed.");
            }

            if (processed) continue;
            await WaitForWorkAsync(stoppingToken);
        }
    }

    /// <summary>Claims and runs one due job. Returns false when nothing was due.</summary>
    internal async Task<bool> RunOnceAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var handlers = BackgroundJobHandlers.Map(scope.ServiceProvider.GetServices<IBackgroundJobHandler>());
        var queue = scope.ServiceProvider.GetRequiredService<IBackgroundJobQueue>();

        var job = await queue.ClaimNextAsync([.. handlers.Keys], cancellationToken);
        if (job is null) return false;

        string? result;
        try
        {
            result = await handlers[job.JobType].HandleAsync(job, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Stopping: leave the job processing; RecoverStuckAsync returns it at the next start.
            throw;
        }
        catch (Exception ex)
        {
            var exhausted = job.AttemptCount >= _options.MaxAttempts;
            metrics?.BackgroundJobFailures.Add(1,
                new KeyValuePair<string, object?>("job_type", job.JobType),
                new KeyValuePair<string, object?>("outcome", exhausted ? "failed" : "retry"));
            if (exhausted)
                await queue.FailAsync(job, ex.Message, cancellationToken);
            else
                await queue.ScheduleRetryAsync(job, ex.Message,
                    clock.GetUtcNow().UtcDateTime + RetryDelay(job.AttemptCount, _options), cancellationToken);
            return true;
        }

        await queue.CompleteAsync(job, result, cancellationToken);
        return true;
    }

    /// <summary>
    /// Returns jobs left processing by a previous run to pending. A failure here is logged, not
    /// thrown: an uncaught exception would stop every other QueueConsumer service with this host,
    /// and the hourly housekeeping pass recovers the jobs later anyway.
    /// </summary>
    internal async Task RecoverAtStartupAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<IBackgroundJobQueue>().RecoverStuckAsync(cancellationToken);
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Startup recovery of processing background jobs failed; housekeeping will retry.");
        }
    }

    /// <summary>
    /// At most once per hour: returns jobs processing longer than <c>ProcessingTimeoutMinutes</c> to
    /// pending, and deletes finished jobs past retention.
    /// </summary>
    internal async Task HousekeepingIfDueAsync(CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        if (_lastHousekeeping is { } last && now - last < HousekeepingInterval) return;
        _lastHousekeeping = now;

        await using var scope = scopeFactory.CreateAsyncScope();
        var queue = scope.ServiceProvider.GetRequiredService<IBackgroundJobQueue>();
        await queue.RecoverStaleAsync(now.UtcDateTime.AddMinutes(-_options.ProcessingTimeoutMinutes), cancellationToken);
        await queue.DeleteFinishedBeforeAsync(now.UtcDateTime.AddDays(-_options.RetentionDays), cancellationToken);
    }

    private async Task WaitForWorkAsync(CancellationToken stoppingToken)
    {
        using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var wake = signal.WaitToReadAsync(wait.Token).AsTask();
        var poll = Task.Delay(TimeSpan.FromSeconds(_options.PollIntervalSeconds), clock, wait.Token);
        await Task.WhenAny(wake, poll);
        await wait.CancelAsync();
        signal.Drain();
    }
}
