using Qertum.Services;
using Qertum.Services.Dashboard;

namespace Qertum.Tests.Dashboard;

public sealed class ApprovalAttentionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTimeOffset Now = new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero);
    private static FixedTimeProvider Clock => new(Now);

    private static ApprovalRequest Row(string subject, ApprovalStatus status, double hoursOld = 1) => new()
    {
        Operation = ApprovalOperations(), TargetId = Guid.NewGuid().ToString(), RequestedBySubject = subject, RequestedByName = subject,
        RequestedAtUtc = Now.UtcDateTime.AddHours(-hoursOld), Status = status
    };

    private static string ApprovalOperations() => Qertum.Services.Approvals.ApprovalOperations.BulkRevoke;

    private static AttentionAccess Admin(string subject) => new(true, true, IsAdmin: true, Subject: subject);

    [Fact]
    public async Task AnAdmin_SeesTheOthersPendingRequests_AndNotTheirOwnOrExpiredOnes()
    {
        await using var scope = await AttentionTestDb.CreateAsync(Ct);
        scope.Db.ApprovalRequests.AddRange(
            Row("sub-bob", ApprovalStatus.Pending), Row("sub-carol", ApprovalStatus.Pending),
            Row("sub-alice", ApprovalStatus.Pending),                       // their own
            Row("sub-dave", ApprovalStatus.Pending, hoursOld: 30),          // past the 24 h request lifetime
            Row("sub-erin", ApprovalStatus.Approved));                      // already decided
        await scope.Db.SaveChangesAsync(Ct);

        var report = await scope.CreateService(Clock).GetReportAsync(Admin("sub-alice"), Ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.ApprovalsWaiting);
        Assert.Equal(2, item.Count);
        Assert.Equal("/approvals", item.ActionHref);
    }

    [Fact]
    public async Task NoPendingRequests_ReportsNothing()
    {
        await using var scope = await AttentionTestDb.CreateAsync(Ct);

        var report = await scope.CreateService(Clock).GetReportAsync(Admin("sub-alice"), Ct);

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.ApprovalsWaiting);
        Assert.Empty(report.WithheldKinds);
    }

    [Fact]
    public async Task ANonAdmin_HasTheKindWithheld()
    {
        await using var scope = await AttentionTestDb.CreateAsync(Ct);
        scope.Db.ApprovalRequests.Add(Row("sub-bob", ApprovalStatus.Pending));
        await scope.Db.SaveChangesAsync(Ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything with { IsAdmin = false }, Ct);

        Assert.Contains(AttentionKind.ApprovalsWaiting, report.WithheldKinds);
        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.ApprovalsWaiting);
    }
}
