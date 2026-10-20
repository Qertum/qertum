using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Approvals;
using Qertum.Tests.BulkOperations;

namespace Qertum.Tests.Approvals;

public sealed class ApprovalSweeperTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly SharedInMemoryDatabase _database = SharedInMemoryDatabase.Create(createSchema: true);
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));
    private readonly RecordingAudit _audit = new();
    private readonly RecordingWebhooks _webhooks = new();

    private DateTime Now => _clock.GetUtcNow().UtcDateTime;

    private ApprovalSweeper NewSweeper() => new(_database.CreateContext(), Options.Create(new ApprovalOptions()), _audit, _webhooks, _clock);

    private async Task<ApprovalRequestId> SeedAsync(ApprovalStatus status, DateTime requestedAt, DateTime? grantUntil = null)
    {
        await using var db = _database.CreateContext();
        var row = new ApprovalRequest
        {
            Operation = ApprovalOperations.BulkRevoke, TargetId = Guid.NewGuid().ToString(), RequestedBySubject = "sub-a", RequestedByName = "a",
            RequestedAtUtc = requestedAt, Status = status, GrantExpiresAtUtc = grantUntil
        };
        db.ApprovalRequests.Add(row);
        await db.SaveChangesAsync(Ct);
        return row.Id;
    }

    private async Task<ApprovalRequest?> ReadAsync(ApprovalRequestId id)
    {
        await using var db = _database.CreateContext();
        return await db.ApprovalRequests.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, Ct);
    }

    [Fact]
    public async Task Sweep_ExpiresStalePendingAndApproved_AndLeavesOpenOnesAlone()
    {
        var stalePending = await SeedAsync(ApprovalStatus.Pending, Now.AddHours(-25));
        var staleApproved = await SeedAsync(ApprovalStatus.Approved, Now.AddHours(-2), grantUntil: Now.AddMinutes(-1));
        var openPending = await SeedAsync(ApprovalStatus.Pending, Now.AddHours(-1));
        var openApproved = await SeedAsync(ApprovalStatus.Approved, Now.AddMinutes(-5), grantUntil: Now.AddMinutes(10));

        var result = await NewSweeper().RunAsync(Ct);

        Assert.Equal(2, result.Expired);
        Assert.Equal(ApprovalStatus.Expired, (await ReadAsync(stalePending))!.Status);
        Assert.Equal(ApprovalStatus.Expired, (await ReadAsync(staleApproved))!.Status);
        Assert.Equal(ApprovalStatus.Pending, (await ReadAsync(openPending))!.Status);
        Assert.Equal(ApprovalStatus.Approved, (await ReadAsync(openApproved))!.Status);
    }

    [Fact]
    public async Task Sweep_AuditsOneExpiredEntryPerRow_AndNotAgainOnTheNextRun()
    {
        await SeedAsync(ApprovalStatus.Pending, Now.AddHours(-25));
        await SeedAsync(ApprovalStatus.Approved, Now.AddHours(-2), grantUntil: Now.AddMinutes(-1));

        await NewSweeper().RunAsync(Ct);
        await NewSweeper().RunAsync(Ct);

        Assert.Equal(2, _audit.Entries.Count(e => e.Action == "ApprovalExpired"));
        var announced = _webhooks.Events.Where(e => e.EventType == "ApprovalExpired").ToList();
        Assert.Equal(2, announced.Count);
        Assert.All(announced, e => Assert.Equal("Expired", e.Fields!["status"]));
    }

    [Fact]
    public async Task Sweep_DeletesFinishedRowsOlderThanRetention_AndKeepsRecentOnes()
    {
        var oldDenied = await SeedAsync(ApprovalStatus.Denied, Now.AddDays(-400));
        var oldUsed = await SeedAsync(ApprovalStatus.Used, Now.AddDays(-400));
        var oldExpired = await SeedAsync(ApprovalStatus.Expired, Now.AddDays(-400));
        var recentDenied = await SeedAsync(ApprovalStatus.Denied, Now.AddDays(-10));
        var oldOpen = await SeedAsync(ApprovalStatus.Pending, Now.AddDays(-10));

        var result = await NewSweeper().RunAsync(Ct);

        Assert.Equal(3, result.Deleted);
        Assert.Null(await ReadAsync(oldDenied));
        Assert.Null(await ReadAsync(oldUsed));
        Assert.Null(await ReadAsync(oldExpired));
        Assert.NotNull(await ReadAsync(recentDenied));
        Assert.NotNull(await ReadAsync(oldOpen));
    }

    [Fact]
    public async Task TheJob_ReportsItsCounts_AndRunsHourly()
    {
        await SeedAsync(ApprovalStatus.Pending, Now.AddHours(-25));
        var handler = new ApprovalRetentionJobHandler(NewSweeper());

        var result = await handler.HandleAsync(new BackgroundJob(), Ct);

        Assert.Equal("expired=1, deleted=0", result);
        Assert.Equal(WellKnownJobTypes.ApprovalRetention, ApprovalRetentionJobHandler.Schedule.JobType);
        Assert.Equal(TimeSpan.FromHours(1), ApprovalRetentionJobHandler.Schedule.Interval);
    }
}
