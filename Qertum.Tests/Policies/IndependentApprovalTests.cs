using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IndependentApprovalTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CallerContext Person(string sub, string name, bool ca = true, bool admin = false) => new(sub, name, admin, ca);

    private static async Task<(PolicyTestDb Scope, CertificateRequestService Service, CertificateRequest Pending)> PendingCaAsync(
        string? requestedBySubject = "sub-alice")
    {
        var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(new CertificateRequest
        {
            CommonName = "ca.example", RequestedBy = "alice", RequestedBySubject = requestedBySubject, Type = "SubordinateCA"
        }, "alice", null, null, Person("sub-alice", "alice"), Ct);
        return (scope, service, created);
    }

    private static Task<CertificateRequest?> Approve(CertificateRequestService s, CertificateRequest r, CallerContext c) =>
        s.MarkAsApprovedAsync(r.Id, c.Name, previewReport: null, c, Ct);

    [Fact]
    public async Task TheRequester_CannotApproveTheirOwnCaRequest_AndItStaysPending()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => Approve(service, pending, Person("sub-alice", "alice")));

        Assert.Equal(PolicyEnforcementStage.Approval, ex.Stage);
        Assert.Equal(PolicyRules.SelfApproval, Assert.Single(ex.Decision.Violations).Rule);
        Assert.Equal(CertificateRequestStatus.Pending,
            (await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == pending.Id, Ct)).Status);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "ApprovalBlockedByPolicy");
    }

    [Fact]
    public async Task Admin_IsNotExemptFromIndependence()
    {
        // Review focus 1.
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            Approve(service, pending, Person("sub-alice", "alice", ca: false, admin: true)));
    }

    [Fact]
    public async Task ADifferentApprover_WithThePermission_Approves()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        var approved = await Approve(service, pending, Person("sub-bob", "bob"));

        Assert.Equal(CertificateRequestStatus.Approved, approved!.Status);
    }

    [Fact]
    public async Task ADifferentApprover_WithoutThePermission_IsRefusedByTheCaPermissionRule()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            Approve(service, pending, Person("sub-bob", "bob", ca: false)));

        Assert.Equal(PolicyRules.CaPermission, Assert.Single(ex.Decision.Violations).Rule);
    }

    [Fact]
    public async Task ALegacyRowWithoutASubject_ComparesNames()
    {
        // Review focus 2.
        var (scope, service, pending) = await PendingCaAsync(requestedBySubject: null);
        await using var _ = scope;

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => Approve(service, pending, Person("sub-new", "alice")));
        Assert.NotNull(await Approve(service, pending, Person("sub-new", "bob")));
    }

    [Fact]
    public async Task WhenWaived_TheRequesterMayApprove_AndTheAuditSaysSo()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;
        await service.SetCaApprovalRuleAsync(false, "root-admin", Ct);

        var approved = await Approve(service, pending, Person("sub-alice", "alice"));

        Assert.Equal(CertificateRequestStatus.Approved, approved!.Status);
        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "Approved");
        Assert.Contains(ApprovalAuditDetail.SelfApprovalWaivedNote, entry.Detail);
    }

    [Fact]
    public async Task ALeafRequest_MayBeApprovedByItsRequester()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var leaf = await service.CreateAsync(new CertificateRequest
        { CommonName = "a.example", RequestedBy = "alice", RequestedBySubject = "sub-alice", Type = "WebServer" }, "alice", Ct);

        Assert.NotNull(await Approve(service, leaf, Person("sub-alice", "alice", ca: false)));
    }

    [Fact]
    public async Task ApprovalPreview_NamesSelfApproval_WithoutWritingAnythingButItsAuditEntry()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        var preview = await scope.CreatePreviewService()
            .PreviewApprovalAsync(pending, "alice", Person("sub-alice", "alice"), Ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.SelfApproval);
        Assert.Equal(CertificateRequestStatus.Pending,
            (await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == pending.Id, Ct)).Status);
        Assert.Single(scope.Audit.Entries, e => e.Action == "ApprovalPreviewed");
    }

    [Fact]
    public async Task TheConsumer_AndAutoApproval_AreNotAffected()
    {
        var (scope, service, pending) = await PendingCaAsync();
        await using var _ = scope;

        // No caller: the legacy path used by tests and internal callers is unchanged.
        Assert.NotNull(await service.MarkAsApprovedAsync(pending.Id, "approver", Ct));
        var decision = await service.CheckIssuancePolicyAsync(pending.Id, Ct);
        Assert.True(decision.Allowed);
    }
}
