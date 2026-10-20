using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Lifecycle;
using Qertum.Tests.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

public sealed class BackgroundJobProcessorTests
{
    private const string Type = "TestJob";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly SharedInMemoryDatabase _database = SharedInMemoryDatabase.Create(createSchema: true);
    private readonly RecordingDiagnosticEventLog _diagnostics = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 9, 25, 8, 0, 0, TimeSpan.Zero));
    private readonly BackgroundJobOptions _options = new();

    private sealed class ScriptedHandler(string jobType, Func<BackgroundJob, CancellationToken, Task<string?>> run) : IBackgroundJobHandler
    {
        public string JobType => jobType;
        public Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken) => run(job, cancellationToken);
    }

    private BackgroundJobProcessor NewProcessor(params IBackgroundJobHandler[] handlers) => NewProcessor(null, handlers);

    private BackgroundJobProcessor NewProcessor(OperationsMetrics? metrics, params IBackgroundJobHandler[] handlers)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        _database.ReplaceDbContext(services);
        services.AddSingleton<TimeProvider>(_clock);
        services.AddSingleton<IDiagnosticEventLog>(_diagnostics);
        services.AddScoped<IBackgroundJobQueue, BackgroundJobQueue>();
        foreach (var handler in handlers)
            services.AddScoped<IBackgroundJobHandler>(_ => handler);
        var provider = services.BuildServiceProvider();
        return new BackgroundJobProcessor(provider.GetRequiredService<IServiceScopeFactory>(), new BackgroundJobChannel(),
            Options.Create(_options), NullLogger<BackgroundJobProcessor>.Instance, _clock, metrics);
    }

    private async Task<BackgroundJob> EnqueueAsync(string type = Type)
    {
        var queue = new BackgroundJobQueue(_database.CreateContext(), _diagnostics, NullLogger<BackgroundJobQueue>.Instance, _clock);
        return (await queue.EnqueueAsync(type, null, "test", null, cancellationToken: Ct))!;
    }

    private async Task<BackgroundJob> StoredAsync(BackgroundJobId id)
    {
        await using var db = _database.CreateContext();
        return await db.BackgroundJobs.AsNoTracking().SingleAsync(j => j.Id == id, Ct);
    }

    [Fact]
    public async Task RunOnce_DispatchesToTheHandler_AndCompletesWithItsResult()
    {
        var job = await EnqueueAsync();
        BackgroundJob? seen = null;
        var processor = NewProcessor(new ScriptedHandler(Type, (j, _) => { seen = j; return Task.FromResult<string?>("done"); }));

        Assert.True(await processor.RunOnceAsync(Ct));

        Assert.Equal(job.Id, seen!.Id);
        var stored = await StoredAsync(job.Id);
        Assert.Equal(BackgroundJobStatus.Completed, stored.Status);
        Assert.Equal("done", stored.Result);
        Assert.False(await processor.RunOnceAsync(Ct));
    }

    [Fact]
    public async Task RunOnce_WhenTheHandlerThrows_SchedulesARetryWithExponentialBackoff()
    {
        var job = await EnqueueAsync();
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => throw new InvalidOperationException("boom")));

        await processor.RunOnceAsync(Ct);
        var afterFirst = await StoredAsync(job.Id);
        Assert.Equal(BackgroundJobStatus.Pending, afterFirst.Status);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime.AddSeconds(30), afterFirst.NextAttemptAfterUtc);
        Assert.Equal("boom", afterFirst.FailureReason);

        _clock.Advance(TimeSpan.FromSeconds(30));
        await processor.RunOnceAsync(Ct);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime.AddSeconds(60), (await StoredAsync(job.Id)).NextAttemptAfterUtc);
    }

    [Fact]
    public async Task RunOnce_AfterMaxAttempts_MarksTheJobFailed()
    {
        _options.MaxAttempts = 2;
        var job = await EnqueueAsync();
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => throw new InvalidOperationException("boom")));

        await processor.RunOnceAsync(Ct);
        _clock.Advance(TimeSpan.FromHours(1));
        await processor.RunOnceAsync(Ct);

        var stored = await StoredAsync(job.Id);
        Assert.Equal(BackgroundJobStatus.Failed, stored.Status);
        Assert.Equal(2, stored.AttemptCount);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobFailed);
    }

    [Fact]
    public async Task RunOnce_CountsEachFailedAttemptByJobTypeAndOutcome()
    {
        _options.MaxAttempts = 2;
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = new OperationsMetrics(meters);
        await EnqueueAsync();
        var processor = NewProcessor(metrics, new ScriptedHandler(Type, (_, _) => throw new InvalidOperationException("boom")));

        await processor.RunOnceAsync(Ct);
        Assert.Equal(1, recorder.Sum("ca.background_job.failures", ("job_type", Type), ("outcome", "retry")));
        Assert.Equal(0, recorder.Sum("ca.background_job.failures", ("outcome", "failed")));

        _clock.Advance(TimeSpan.FromHours(1));
        await processor.RunOnceAsync(Ct);
        Assert.Equal(1, recorder.Sum("ca.background_job.failures", ("job_type", Type), ("outcome", "failed")));
    }

    [Fact]
    public async Task RunOnce_DoesNotCountASuccessfulJob()
    {
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = new OperationsMetrics(meters);
        await EnqueueAsync();
        var processor = NewProcessor(metrics, new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>("ok")));

        await processor.RunOnceAsync(Ct);

        Assert.Equal(0, recorder.Sum("ca.background_job.failures"));
    }

    [Fact]
    public async Task RunOnce_LeavesJobsWithoutAHandlerPending()
    {
        var job = await EnqueueAsync("NobodyHandlesThis");
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null)));

        Assert.False(await processor.RunOnceAsync(Ct));
        Assert.Equal(BackgroundJobStatus.Pending, (await StoredAsync(job.Id)).Status);
    }

    [Fact]
    public async Task RunOnce_CancelledDuringHandler_LeavesTheJobProcessing()
    {
        var job = await EnqueueAsync();
        using var stopping = new CancellationTokenSource();
        var processor = NewProcessor(new ScriptedHandler(Type, (_, token) =>
        {
            stopping.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.FromResult<string?>(null);
        }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processor.RunOnceAsync(stopping.Token));

        var stored = await StoredAsync(job.Id);
        Assert.Equal(BackgroundJobStatus.Processing, stored.Status);
        Assert.DoesNotContain(_diagnostics.Entries, e => e.Action is DiagnosticActions.JobRetryScheduled or DiagnosticActions.JobFailed);
    }

    [Fact]
    public void Handlers_WithADuplicateJobType_AreRefused()
    {
        var a = new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null));
        var b = new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null));

        Assert.Throws<InvalidOperationException>(() => BackgroundJobHandlers.Map([a, b]));
    }

    [Theory]
    [InlineData(1, 30)]
    [InlineData(2, 60)]
    [InlineData(3, 120)]
    [InlineData(8, 3600)]
    [InlineData(40, 3600)]
    public void RetryDelay_DoublesAndIsCapped(int attempt, int expectedSeconds)
        => Assert.Equal(TimeSpan.FromSeconds(expectedSeconds), BackgroundJobProcessor.RetryDelay(attempt, new BackgroundJobOptions()));

    [Fact]
    public async Task Housekeeping_DeletesOldFinishedJobs()
    {
        _options.RetentionDays = 1;
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null)));
        var old = await EnqueueAsync();
        await processor.RunOnceAsync(Ct);
        _clock.Advance(TimeSpan.FromDays(2));
        var recent = await EnqueueAsync();
        await processor.RunOnceAsync(Ct);

        await processor.HousekeepingIfDueAsync(Ct);

        Assert.False(await ExistsAsync(old.Id));
        Assert.True(await ExistsAsync(recent.Id));
    }

    [Fact]
    public async Task Housekeeping_SkipsWhenThePreviousPruneWasUnderAnHourAgo()
    {
        _options.RetentionDays = 1;
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null)));
        await processor.HousekeepingIfDueAsync(Ct); // first prune, nothing to delete

        var job = await EnqueueAsync();
        await processor.RunOnceAsync(Ct);
        // Make the job old without moving the clock an hour: backdate it directly.
        await using (var db = _database.CreateContext())
            await db.BackgroundJobs.Where(j => j.Id == job.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(j => j.CompletedAtUtc, _clock.GetUtcNow().UtcDateTime.AddDays(-5)), Ct);
        _clock.Advance(TimeSpan.FromMinutes(59));

        await processor.HousekeepingIfDueAsync(Ct);
        Assert.True(await ExistsAsync(job.Id));

        _clock.Advance(TimeSpan.FromMinutes(1));
        await processor.HousekeepingIfDueAsync(Ct);
        Assert.False(await ExistsAsync(job.Id));
    }

    [Fact]
    public async Task Housekeeping_RecoversAJobStuckProcessingPastTheTimeout()
    {
        _options.ProcessingTimeoutMinutes = 30;
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>("done")));
        await processor.HousekeepingIfDueAsync(Ct); // first pass, nothing stuck yet
        var queue = new BackgroundJobQueue(_database.CreateContext(), _diagnostics, NullLogger<BackgroundJobQueue>.Instance, _clock);
        var job = await queue.EnqueueAsync(Type, "k", "test", null, cancellationToken: Ct);
        // Claimed, then the bookkeeping that should have completed it never ran.
        await queue.ClaimNextAsync([Type], Ct);

        // An hour later: housekeeping is due again and the claim is past the 30-minute timeout.
        _clock.Advance(TimeSpan.FromHours(1));
        await processor.HousekeepingIfDueAsync(Ct);
        Assert.Equal(BackgroundJobStatus.Pending, (await StoredAsync(job!.Id)).Status);

        Assert.True(await processor.RunOnceAsync(Ct));
        Assert.Equal(BackgroundJobStatus.Completed, (await StoredAsync(job.Id)).Status);
    }

    [Fact]
    public async Task Housekeeping_LeavesAJobProcessingWithinTheTimeout()
    {
        var processor = NewProcessor(new ScriptedHandler(Type, (_, _) => Task.FromResult<string?>(null)));
        var queue = new BackgroundJobQueue(_database.CreateContext(), _diagnostics, NullLogger<BackgroundJobQueue>.Instance, _clock);
        var job = await queue.EnqueueAsync(Type, null, "test", null, cancellationToken: Ct);
        await queue.ClaimNextAsync([Type], Ct);
        _clock.Advance(TimeSpan.FromMinutes(_options.ProcessingTimeoutMinutes - 1));

        await processor.HousekeepingIfDueAsync(Ct);

        Assert.Equal(BackgroundJobStatus.Processing, (await StoredAsync(job!.Id)).Status);
    }

    [Fact]
    public async Task StartupRecovery_WhenTheDatabaseFails_DoesNotStopTheProcessor()
    {
        var services = new ServiceCollection();
        services.AddScoped<IBackgroundJobQueue, RecoveryFailsQueue>();
        var provider = services.BuildServiceProvider();
        var processor = new BackgroundJobProcessor(provider.GetRequiredService<IServiceScopeFactory>(), new BackgroundJobChannel(),
            Options.Create(_options), NullLogger<BackgroundJobProcessor>.Instance, _clock);

        await processor.RecoverAtStartupAsync(Ct);
    }

    private sealed class RecoveryFailsQueue : IBackgroundJobQueue
    {
        public Task<int> RecoverStuckAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException("database is locked");
        public Task<int> RecoverStaleAsync(DateTime claimedBeforeUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<BackgroundJob?> EnqueueAsync(string jobType, string? concurrencyKey, string requestedBy, string? reason, string? payloadJson = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<BackgroundJob?> ClaimNextAsync(IReadOnlyCollection<string> handledJobTypes, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task CompleteAsync(BackgroundJob job, string? result, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task ScheduleRetryAsync(BackgroundJob job, string error, DateTime nextAttemptAfterUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task FailAsync(BackgroundJob job, string error, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<int> DeleteFinishedBeforeAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    private async Task<bool> ExistsAsync(BackgroundJobId id)
    {
        await using var db = _database.CreateContext();
        return await db.BackgroundJobs.AnyAsync(j => j.Id == id, Ct);
    }
}
