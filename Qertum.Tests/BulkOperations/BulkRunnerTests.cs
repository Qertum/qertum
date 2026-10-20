using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.BulkOperations;
using Qertum.Services.Policies;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkRunnerTests
{
    private sealed class FakeActions : IBulkItemActions
    {
        public List<CertificateRequestId> Revoked { get; } = [];
        public List<(CertificateRequestId Id, CallerContext Caller)> Renewed { get; } = [];
        public HashSet<CertificateRequestId> NoLongerIssued { get; } = [];
        public Dictionary<CertificateRequestId, Exception> Throws { get; } = [];
        public Action<CertificateRequestId>? OnRevoke { get; set; }

        public Task<bool> RevokeAsync(CertificateRequestId id, string reason, string performedBy, CancellationToken ct)
        {
            OnRevoke?.Invoke(id);
            if (Throws.TryGetValue(id, out var ex)) throw ex;
            if (NoLongerIssued.Contains(id)) return Task.FromResult(false);
            Revoked.Add(id);
            return Task.FromResult(true);
        }

        public Task<CertificateRequestId> RenewAsync(CertificateRequestId id, string performedBy, CallerContext caller, CancellationToken ct)
        {
            if (Throws.TryGetValue(id, out var ex)) throw ex;
            Renewed.Add((id, caller));
            return Task.FromResult(new CertificateRequestId(Guid.NewGuid()));
        }
    }

    private static async Task<(BulkOperationId Id, List<CertificateRequestId> Requests)> RunningAsync(
        BulkScope scope, BulkOperationKind kind, int certificates)
    {
        var requests = new List<CertificateRequestId>();
        for (var i = 0; i < certificates; i++) requests.Add(await scope.AddIssuedAsync($"c{i}.example"));
        var service = scope.CreateService();
        var preview = await service.PreviewAsync(
            new(kind, new BulkOperationFilter { All = true }, kind == BulkOperationKind.Revoke ? "compromised" : null), BulkScope.Operator);
        await service.ExecuteAsync(preview.Operation.Id, certificates, new BulkActor("sub-ex", "executor", false, true));
        return (preview.Operation.Id, requests);
    }

    private static BulkOperationRunner Runner(BulkScope scope, IBulkItemActions actions) =>
        new(scope.NewDb(), actions, scope.Audit, scope.Webhooks, NullLogger<BulkOperationRunner>.Instance, scope.Clock);

    [Fact]
    public async Task Revoke_ProcessesEveryItem_AsTheExecutor_AndCompletes()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, requests) = await RunningAsync(scope, BulkOperationKind.Revoke, 3);
        var actions = new FakeActions();

        var summary = await Runner(scope, actions).RunAsync(id, TestContext.Current.CancellationToken);

        Assert.Equal(3, actions.Revoked.Count);
        Assert.Contains("done=3", summary);
        await using var db = scope.NewDb();
        var op = await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BulkOperationStatus.Completed, op.Status);
        Assert.Equal((3, 0, 0), (op.DoneCount, op.SkippedCount, op.FailedCount));
        Assert.NotNull(op.FinishedAtUtc);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "BulkOperationCompleted");
        var evt = Assert.Single(scope.Webhooks.Events);
        Assert.Equal("BulkOperationCompleted", evt.EventType);
        Assert.Equal("3", evt.Fields!["doneCount"]);
        Assert.DoesNotContain("commonName", evt.Fields!.Keys);
    }

    [Fact]
    public async Task ItemNoLongerIssued_IsSkipped_AndTheRunContinues()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, requests) = await RunningAsync(scope, BulkOperationKind.Revoke, 3);
        var actions = new FakeActions();
        actions.NoLongerIssued.Add(requests[1]);

        await Runner(scope, actions).RunAsync(id, TestContext.Current.CancellationToken);

        await using var db = scope.NewDb();
        var op = await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BulkOperationStatus.Completed, op.Status);
        Assert.Equal((2, 1, 0), (op.DoneCount, op.SkippedCount, op.FailedCount));
        Assert.Equal(1, await db.BulkOperationItems.CountAsync(i => i.Outcome == BulkItemOutcome.Skipped, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ItemThatThrows_IsFailedWithItsReason_AndTheOperationCompletesWithErrors()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, requests) = await RunningAsync(scope, BulkOperationKind.Renew, 2);
        var actions = new FakeActions();
        actions.Throws[requests[0]] = new InvalidOperationException("Blocked by issuance policy: key too small");

        await Runner(scope, actions).RunAsync(id, TestContext.Current.CancellationToken);

        await using var db = scope.NewDb();
        var op = await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BulkOperationStatus.CompletedWithErrors, op.Status);
        Assert.Equal((1, 0, 1), (op.DoneCount, op.SkippedCount, op.FailedCount));
        var failed = await db.BulkOperationItems.SingleAsync(i => i.Outcome == BulkItemOutcome.Failed, TestContext.Current.CancellationToken);
        Assert.Contains("key too small", failed.Detail);
        var done = await db.BulkOperationItems.SingleAsync(i => i.Outcome == BulkItemOutcome.Done, TestContext.Current.CancellationToken);
        Assert.NotNull(done.ResultRequestId);
    }

    [Fact]
    public async Task Renew_RebuildsTheCallerFromTheStoredSnapshot()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, _) = await RunningAsync(scope, BulkOperationKind.Renew, 1);
        var actions = new FakeActions();

        await Runner(scope, actions).RunAsync(id, TestContext.Current.CancellationToken);

        var (_, caller) = Assert.Single(actions.Renewed);
        Assert.Equal("sub-ex", caller.Subject);
        Assert.Equal("executor", caller.Name);
        Assert.False(caller.IsAdmin);
        Assert.True(caller.HoldsCaPermission);
    }

    [Fact]
    public async Task Rerun_AfterACrash_NeverRepeatsADoneItem()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, requests) = await RunningAsync(scope, BulkOperationKind.Revoke, 3);
        var first = new FakeActions();
        // The process dies on the second item: cancellation escapes the runner without finishing the operation.
        using var cts = new CancellationTokenSource();
        first.OnRevoke = r => { if (r == requests.OrderBy(x => x.Value).ElementAt(1)) cts.Cancel(); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Runner(scope, first).RunAsync(id, cts.Token));

        var second = new FakeActions();
        await Runner(scope, second).RunAsync(id, TestContext.Current.CancellationToken);

        Assert.Empty(first.Revoked.Intersect(second.Revoked));
        await using var db = scope.NewDb();
        var op = await db.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(BulkOperationStatus.Completed, op.Status);
        Assert.Equal(3, op.DoneCount);
        Assert.Equal(1, scope.Audit.Entries.Count(e => e.Action == "BulkOperationCompleted"));
    }

    [Fact]
    public async Task OperationThatIsNotRunning_IsLeftAlone()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddIssuedAsync("a.example");
        var preview = await scope.CreateService().PreviewAsync(
            new(BulkOperationKind.Revoke, new BulkOperationFilter { All = true }, "r"), BulkScope.Operator, TestContext.Current.CancellationToken);
        var actions = new FakeActions();

        var summary = await Runner(scope, actions).RunAsync(preview.Operation.Id, TestContext.Current.CancellationToken);

        Assert.Empty(actions.Revoked);
        Assert.Contains("not running", summary);
    }

    [Fact]
    public async Task Renew_SkipsASourceThatLeftIssued_OrGainedARenewal_SincePreview()
    {
        await using var scope = await BulkScope.CreateAsync();
        var (id, requests) = await RunningAsync(scope, BulkOperationKind.Renew, 3);
        var ordered = requests.OrderBy(r => r.Value).ToList();
        await using (var db = scope.NewDb())
        {
            // ordered[0] was revoked by hand after the preview; ordered[1] was renewed by hand; ordered[2] is untouched.
            await db.CertificateRequests.Where(r => r.Id == ordered[0])
                .ExecuteUpdateAsync(u => u.SetProperty(r => r.Status, CertificateRequestStatus.Revoked), TestContext.Current.CancellationToken);
        }
        await scope.AddRenewalOfAsync(ordered[1], CertificateRequestStatus.Pending);
        var actions = new FakeActions();

        await Runner(scope, actions).RunAsync(id, TestContext.Current.CancellationToken);

        Assert.Equal([ordered[2]], actions.Renewed.Select(r => r.Id).ToList());
        await using var check = scope.NewDb();
        var op = await check.BulkOperations.SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal((1, 2, 0), (op.DoneCount, op.SkippedCount, op.FailedCount));
        Assert.Equal(BulkOperationStatus.Completed, op.Status);
    }
}
