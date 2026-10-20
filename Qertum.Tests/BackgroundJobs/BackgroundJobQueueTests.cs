using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Lifecycle;
using Qertum.Tests.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

public sealed class BackgroundJobQueueTests
{
    private static readonly DateTimeOffset Start = new(2026, 9, 25, 8, 0, 0, TimeSpan.Zero);
    private const string Type = WellKnownJobTypes.CrlRefresh;

    private readonly SharedInMemoryDatabase _database = SharedInMemoryDatabase.Create(createSchema: true);
    private readonly RecordingDiagnosticEventLog _diagnostics = new();
    private readonly FakeTimeProvider _clock = new(Start);

    private BackgroundJobQueue NewQueue() =>
        new(_database.CreateContext(), _diagnostics, NullLogger<BackgroundJobQueue>.Instance, _clock);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<BackgroundJob> StoredAsync(BackgroundJobId id)
    {
        await using var db = _database.CreateContext();
        return await db.BackgroundJobs.AsNoTracking().SingleAsync(j => j.Id == id, Ct);
    }

    [Fact]
    public async Task Enqueue_CreatesAPendingJobDueNow_AndRecordsJobQueued()
    {
        var job = await NewQueue().EnqueueAsync(Type, "crl-refresh", "crl-refresh-scheduler", "base age 12.0 h", cancellationToken: Ct);

        Assert.NotNull(job);
        var stored = await StoredAsync(job!.Id);
        Assert.Equal(BackgroundJobStatus.Pending, stored.Status);
        Assert.Equal(Start.UtcDateTime, stored.RequestedAtUtc);
        Assert.Equal(Start.UtcDateTime, stored.NextAttemptAfterUtc);
        Assert.Equal(0, stored.AttemptCount);

        var entry = Assert.Single(_diagnostics.Entries);
        Assert.Equal(LifecycleSubjectTypes.BackgroundJob, entry.SubjectType);
        Assert.Equal(job.Id.Value, entry.SubjectId);
        Assert.Equal(DiagnosticActions.JobQueued, entry.Action);
        Assert.Equal("crl-refresh-scheduler", entry.PerformedBy);
        Assert.Equal("base age 12.0 h", entry.Detail);
    }

    [Fact]
    public async Task Enqueue_WhileTheKeyIsActive_ReturnsNull_AndRecordsNothingMore()
    {
        Assert.NotNull(await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct));

        var second = await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct);

        Assert.Null(second);
        Assert.Single(_diagnostics.Entries);
        await using var db = _database.CreateContext();
        Assert.Equal(1, await db.BackgroundJobs.CountAsync(Ct));
    }

    [Fact]
    public async Task Claim_TakesOnlyHandledTypesThatAreDue()
    {
        var queue = NewQueue();
        await queue.EnqueueAsync("Other", null, "s", null, cancellationToken: Ct);
        var due = await queue.EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);

        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);

        Assert.Equal(due!.Id, claimed!.Id);
        Assert.Equal(BackgroundJobStatus.Processing, claimed.Status);
        Assert.Equal(1, claimed.AttemptCount);
        Assert.Equal(Start.UtcDateTime, claimed.ClaimedAtUtc);
        Assert.Null(await NewQueue().ClaimNextAsync([Type], Ct));
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobClaimed && e.PerformedBy == "queue-consumer");
    }

    [Fact]
    public async Task Claim_IsExclusiveUnderConcurrency()
    {
        await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => NewQueue().ClaimNextAsync([Type], Ct), Ct)));

        Assert.Single(results, r => r is not null);
    }

    [Fact]
    public async Task Complete_StoresTheResult_AndReleasesTheKey()
    {
        await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct);
        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);
        _clock.Advance(TimeSpan.FromSeconds(3));

        await NewQueue().CompleteAsync(claimed!, "crlNumber=7", Ct);

        var stored = await StoredAsync(claimed!.Id);
        Assert.Equal(BackgroundJobStatus.Completed, stored.Status);
        Assert.Equal("crlNumber=7", stored.Result);
        Assert.Equal(Start.UtcDateTime.AddSeconds(3), stored.CompletedAtUtc);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobCompleted && e.Detail == "crlNumber=7");
        Assert.NotNull(await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct));
    }

    [Fact]
    public async Task ScheduleRetry_ReturnsTheJobToPending_NotClaimableBeforeItsTime()
    {
        await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct);
        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);

        await NewQueue().ScheduleRetryAsync(claimed!, "boom", Start.UtcDateTime.AddSeconds(30), Ct);

        var stored = await StoredAsync(claimed!.Id);
        Assert.Equal(BackgroundJobStatus.Pending, stored.Status);
        Assert.Equal("boom", stored.FailureReason);
        Assert.Null(await NewQueue().ClaimNextAsync([Type], Ct));
        _clock.Advance(TimeSpan.FromSeconds(30));
        var again = await NewQueue().ClaimNextAsync([Type], Ct);
        Assert.Equal(2, again!.AttemptCount);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobRetryScheduled);
    }

    [Fact]
    public async Task Fail_MarksTheJobFailed_AndReleasesTheKey()
    {
        await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct);
        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);

        await NewQueue().FailAsync(claimed!, "gave up", Ct);

        var stored = await StoredAsync(claimed!.Id);
        Assert.Equal(BackgroundJobStatus.Failed, stored.Status);
        Assert.Equal("gave up", stored.FailureReason);
        Assert.Equal(Start.UtcDateTime, stored.CompletedAtUtc);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobFailed && e.Detail == "gave up");
        Assert.NotNull(await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct));
    }

    [Fact]
    public async Task Fail_TruncatesALongReason()
    {
        await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);

        await NewQueue().FailAsync(claimed!, new string('x', 10_000), Ct);

        Assert.Equal(BackgroundJobQueue.MaxFailureReasonLength, (await StoredAsync(claimed!.Id)).FailureReason!.Length);
    }

    [Fact]
    public async Task RecoverStuck_ReturnsProcessingJobsToPending_AndRecordsJobRecovered()
    {
        await NewQueue().EnqueueAsync(Type, "crl-refresh", "s", null, cancellationToken: Ct);
        var claimed = await NewQueue().ClaimNextAsync([Type], Ct);

        var recovered = await NewQueue().RecoverStuckAsync(Ct);

        Assert.Equal(1, recovered);
        Assert.Equal(BackgroundJobStatus.Pending, (await StoredAsync(claimed!.Id)).Status);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobRecovered && e.SubjectId == claimed.Id.Value);
        Assert.NotNull(await NewQueue().ClaimNextAsync([Type], Ct));
    }

    [Fact]
    public async Task RecoverStale_ReturnsOnlyJobsClaimedBeforeTheCutoff()
    {
        await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var stale = await NewQueue().ClaimNextAsync([Type], Ct);
        _clock.Advance(TimeSpan.FromMinutes(40));
        await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var fresh = await NewQueue().ClaimNextAsync([Type], Ct);

        var recovered = await NewQueue().RecoverStaleAsync(_clock.GetUtcNow().UtcDateTime.AddMinutes(-30), Ct);

        Assert.Equal(1, recovered);
        Assert.Equal(BackgroundJobStatus.Pending, (await StoredAsync(stale!.Id)).Status);
        Assert.Equal(BackgroundJobStatus.Processing, (await StoredAsync(fresh!.Id)).Status);
        Assert.Contains(_diagnostics.Entries, e => e.Action == DiagnosticActions.JobRecovered && e.SubjectId == stale.Id.Value);
    }

    [Fact]
    public async Task DeleteFinishedBefore_RemovesOnlyOldFinishedJobs()
    {
        var queue = NewQueue();
        await queue.EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        await queue.EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var old = await NewQueue().ClaimNextAsync([Type], Ct);
        await NewQueue().CompleteAsync(old!, null, Ct);
        var oldFailed = await NewQueue().ClaimNextAsync([Type], Ct);
        await NewQueue().FailAsync(oldFailed!, "x", Ct);
        _clock.Advance(TimeSpan.FromDays(31));
        var pending = await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var recent = await NewQueue().EnqueueAsync(Type, null, "s", null, cancellationToken: Ct);
        var recentClaim = await NewQueue().ClaimNextAsync([Type], Ct);
        await NewQueue().CompleteAsync(recentClaim!, null, Ct);

        var deleted = await NewQueue().DeleteFinishedBeforeAsync(_clock.GetUtcNow().UtcDateTime.AddDays(-30), Ct);

        Assert.Equal(2, deleted);
        await using var db = _database.CreateContext();
        Assert.Equal(2, await db.BackgroundJobs.CountAsync(Ct));
        Assert.NotNull(pending);
        Assert.NotNull(recent);
    }
}
