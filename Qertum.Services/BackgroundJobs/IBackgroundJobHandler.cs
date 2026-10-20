namespace Qertum.Services.BackgroundJobs;

/// <summary>Runs one <see cref="BackgroundJob.JobType"/>. Registered scoped in the processor's host.</summary>
public interface IBackgroundJobHandler
{
    /// <summary>The job type this handler runs; unique across registered handlers.</summary>
    string JobType { get; }

    /// <summary>
    /// Runs the job and returns a short result summary. Throwing schedules a retry (or fails the job
    /// once its attempts are used up); cancellation by the stopping token leaves it processing for
    /// recovery at the next start.
    /// </summary>
    Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken);
}

/// <summary>Builds the job-type → handler map, refusing two handlers for one type.</summary>
public static class BackgroundJobHandlers
{
    public static IReadOnlyDictionary<string, IBackgroundJobHandler> Map(IEnumerable<IBackgroundJobHandler> handlers)
    {
        var map = new Dictionary<string, IBackgroundJobHandler>(StringComparer.Ordinal);
        foreach (var handler in handlers)
            if (!map.TryAdd(handler.JobType, handler))
                throw new InvalidOperationException($"More than one background job handler is registered for '{handler.JobType}'.");
        return map;
    }
}
