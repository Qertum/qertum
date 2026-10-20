using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.BulkOperations;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkExecuteTests
{
    private static async Task<(BulkScope Scope, BulkOperationService Service, BulkOperationView Op)> PreviewedAsync(int certificates = 2)
    {
        var scope = await BulkScope.CreateAsync();
        for (var i = 0; i < certificates; i++) await scope.AddIssuedAsync($"c{i}.example");
        var service = scope.CreateService();
        var preview = await service.PreviewAsync(
            new(BulkOperationKind.Revoke, new BulkOperationFilter { All = true }, "compromised"), BulkScope.Operator, TestContext.Current.CancellationToken);
        return (scope, service, preview.Operation);
    }

    [Fact]
    public async Task Execute_WithTheRightCount_StartsTheJobAndStoresTheCaller()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;
        var actor = new BulkActor("sub-ex", "executor", IsAdmin: true, HoldsCaPermission: false);

        var view = await service.ExecuteAsync(op.Id, confirmCount: 2, actor, TestContext.Current.CancellationToken);

        Assert.Equal(BulkOperationStatus.Running, view.Status);
        var job = Assert.Single(scope.Jobs.Jobs);
        Assert.Equal(WellKnownJobTypes.BulkOperation, job.JobType);
        Assert.Equal($"bulk-operation:{op.Id}", job.ConcurrencyKey);
        Assert.Contains(op.Id.ToString(), job.PayloadJson);
        await using var db = scope.NewDb();
        var stored = await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        var snapshot = JsonSerializer.Deserialize<BulkCallerSnapshot>(stored.CallerSnapshotJson!, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(new BulkCallerSnapshot("sub-ex", "executor", true, false), snapshot);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "BulkOperationStarted" && e.PerformedBy == "executor");
    }

    [Fact]
    public async Task Execute_WithTheWrongCount_IsConflict_AndStartsNothing()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() => service.ExecuteAsync(op.Id, 1, BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(409, ex.StatusCode);
        Assert.Empty(scope.Jobs.Jobs);
        await using var db = scope.NewDb();
        Assert.Equal(BulkOperationStatus.Previewed, (await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task Execute_Twice_SecondIsConflict_AndOnlyOneJobExists()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;
        await service.ExecuteAsync(op.Id, 2, BulkScope.Operator, TestContext.Current.CancellationToken);

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() => service.ExecuteAsync(op.Id, 2, BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(409, ex.StatusCode);
        Assert.Single(scope.Jobs.Jobs);
    }

    [Fact]
    public async Task Execute_AfterTheTtl_IsGone_AndTheOperationExpires()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;
        scope.Clock.Advance(TimeSpan.FromMinutes(61));

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() => service.ExecuteAsync(op.Id, 2, BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(410, ex.StatusCode);
        Assert.Empty(scope.Jobs.Jobs);
        Assert.Equal(BulkOperationStatus.Expired, (await service.GetAsync(op.Id, TestContext.Current.CancellationToken))!.Status);
    }

    [Fact]
    public async Task Execute_UnknownOperation_IsNotFound()
    {
        await using var scope = await BulkScope.CreateAsync();
        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService().ExecuteAsync(new BulkOperationId(Guid.NewGuid()), 1, BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(404, ex.StatusCode);
    }

    [Fact]
    public async Task Cancel_OnlyWhilePreviewed()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;

        var cancelled = await service.CancelAsync(op.Id, BulkScope.Operator, TestContext.Current.CancellationToken);
        Assert.Equal(BulkOperationStatus.Cancelled, cancelled.Status);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "BulkOperationCancelled");

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() => service.ExecuteAsync(op.Id, 2, BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(409, ex.StatusCode);
        var again = await Assert.ThrowsAsync<BulkOperationException>(() => service.CancelAsync(op.Id, BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(409, again.StatusCode);
    }

    [Fact]
    public async Task Reads_ListOwnOperationsOnly_UnlessNoSubjectFilterIsGiven()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;

        Assert.Single((await service.ListAsync(1, 10, creatorSubject: BulkScope.Operator.Subject, TestContext.Current.CancellationToken)).Items);
        Assert.Empty((await service.ListAsync(1, 10, creatorSubject: "someone-else", TestContext.Current.CancellationToken)).Items);
        Assert.Single((await service.ListAsync(1, 10, creatorSubject: null, TestContext.Current.CancellationToken)).Items);
        Assert.Equal(2, (await service.GetItemsAsync(op.Id, null, 1, 10, TestContext.Current.CancellationToken))!.TotalCount);
        Assert.Equal(0, (await service.GetItemsAsync(op.Id, BulkItemOutcome.Done, 1, 10, TestContext.Current.CancellationToken))!.TotalCount);
        Assert.Null(await service.GetItemsAsync(new BulkOperationId(Guid.NewGuid()), null, 1, 10, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Access_CreatorOrAdminOnly_AndPermissionPerKind()
    {
        var op = new BulkOperationView { CreatedBySubject = "sub-1", CreatedBy = "alice", Kind = BulkOperationKind.Revoke };
        Assert.True(BulkOperationAccess.CanSee(op, new BulkActor("sub-1", "alice", false, false)));
        Assert.True(BulkOperationAccess.CanSee(op, new BulkActor("sub-9", "root", true, false)));
        Assert.False(BulkOperationAccess.CanSee(op, new BulkActor("sub-2", "bob", false, false)));
        Assert.Equal(AppPermissions.CertificatesManage, BulkOperationAccess.PermissionFor(BulkOperationKind.Revoke));
        Assert.Equal(AppPermissions.CertificatesCreate, BulkOperationAccess.PermissionFor(BulkOperationKind.Renew));
    }

    [Fact]
    public async Task Execute_WhenNoJobCanBeQueued_PutsTheOperationBackToPreviewed()
    {
        var (scope, service, op) = await PreviewedAsync();
        await using var _ = scope;
        // A job already holds the key, so the enqueue is refused after the operation was flipped to Running.
        await scope.Jobs.EnqueueAsync(WellKnownJobTypes.BulkOperation, $"bulk-operation:{op.Id}", "other", null, null, TestContext.Current.CancellationToken);

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() => service.ExecuteAsync(op.Id, 2, BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(409, ex.StatusCode);
        Assert.Equal(BulkOperationStatus.Previewed, (await service.GetAsync(op.Id, TestContext.Current.CancellationToken))!.Status);
    }
}
