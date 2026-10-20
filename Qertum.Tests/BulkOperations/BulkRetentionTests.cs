using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BulkOperations;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkRetentionTests
{
    [Fact]
    public async Task Retention_DeletesFinishedOperationsPastTheirWindow_WithTheirItems_AndKeepsRunningOnes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await BulkScope.CreateAsync();
        var oldFinished = await SeedAsync(scope, BulkOperationStatus.Completed, daysOld: 400, ct);
        var oldRunning = await SeedAsync(scope, BulkOperationStatus.Running, daysOld: 400, ct);
        var recentFinished = await SeedAsync(scope, BulkOperationStatus.Completed, daysOld: 10, ct);

        var handler = new BulkOperationRetentionJobHandler(scope.NewDb(), Options.Create(new BulkOperationsOptions()), scope.Clock);
        var result = await handler.HandleAsync(new BackgroundJob(), ct);

        Assert.Equal("operations=1", result);
        await using var db = scope.NewDb();
        Assert.Null(await db.BulkOperations.FindAsync([oldFinished], ct));
        Assert.Empty(await db.BulkOperationItems.Where(i => i.OperationId == oldFinished).ToListAsync(ct));
        Assert.NotNull(await db.BulkOperations.FindAsync([oldRunning], ct));
        Assert.NotNull(await db.BulkOperations.FindAsync([recentFinished], ct));
        Assert.Single(await db.BulkOperationItems.Where(i => i.OperationId == recentFinished).ToListAsync(ct));
    }

    [Fact]
    public void RetentionSchedule_IsDaily_StartsAfterFiveMinutes()
    {
        Assert.Equal(WellKnownJobTypes.BulkOperationRetention, BulkOperationRetentionJobHandler.Schedule.JobType);
        Assert.Equal(TimeSpan.FromHours(24), BulkOperationRetentionJobHandler.Schedule.Interval);
        Assert.Equal(TimeSpan.FromMinutes(5), BulkOperationRetentionJobHandler.Schedule.InitialDelay);
    }

    private static async Task<BulkOperationId> SeedAsync(BulkScope scope, BulkOperationStatus status, int daysOld, CancellationToken ct)
    {
        await using var db = scope.NewDb();
        var operation = new BulkOperation
        {
            Kind = BulkOperationKind.Revoke, Status = status, CreatedBy = "seed", ItemCount = 1,
            CreatedAtUtc = scope.Clock.GetUtcNow().UtcDateTime.AddDays(-daysOld)
        };
        db.BulkOperations.Add(operation);
        db.BulkOperationItems.Add(new BulkOperationItem { OperationId = operation.Id, RequestId = Guid.NewGuid() });
        await db.SaveChangesAsync(ct);
        return operation.Id;
    }
}
