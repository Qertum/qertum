using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class ApprovalPreviewServiceTests
{
    private static CertificateRequest WebServer(string cn) =>
        new() { CommonName = cn, RequestedBy = "alice", Type = "WebServer" };

    [Fact]
    public async Task Admitted_ReportsTheCurrentVersionAndAuditsOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var created = await scope.CreateRequestService().CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        scope.Audit.Entries.Clear();

        var preview = await scope.CreatePreviewService().PreviewApprovalAsync(created, "approver", ct);

        Assert.True(preview.Allowed);
        Assert.Equal(v1.Id, preview.PolicyVersionId);
        Assert.Equal(1, preview.PolicyVersionNumber);
        Assert.Equal(1, preview.EvaluatedPolicyVersionNumber);
        Assert.False(preview.PolicyChangedSinceEvaluation);
        var entry = Assert.Single(scope.Audit.Entries);
        Assert.Equal("ApprovalPreviewed", entry.Action);
        Assert.Equal("approver", entry.PerformedBy);
        Assert.Equal((Guid)created.Id, entry.ResourceId);
        Assert.Contains("admits this request (same version as its last evaluation)", entry.Detail);
    }

    [Fact]
    public async Task TightenedAfterCreation_ReportsViolationsAndTheChange()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        const string v1PolicyName = "Web servers";
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: v1PolicyName, ct: ct);
        var created = await scope.CreateRequestService().CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        await CertificateRequestPolicyEnforcementTests.PublishNewVersionAsync(scope, v1, ["other.com"], ct);
        scope.Audit.Entries.Clear();

        var preview = await scope.CreatePreviewService().PreviewApprovalAsync(created, "approver", ct);

        Assert.False(preview.Allowed);
        Assert.NotEmpty(preview.Violations);
        Assert.Equal(2, preview.PolicyVersionNumber);
        Assert.Equal(1, preview.EvaluatedPolicyVersionNumber);
        Assert.True(preview.PolicyChangedSinceEvaluation);
        Assert.Equal(v1PolicyName, preview.EvaluatedPolicyName);
        Assert.Contains($"refuses this request (last evaluated under policy '{v1PolicyName}' v1; the policy has changed since)", Assert.Single(scope.Audit.Entries).Detail);
    }

    [Fact]
    public async Task ApprovalPreview_AtEnforce_ListsThePqcViolation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var created = await scope.CreateRequestService().CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        (await scope.Db.Settings.SingleAsync(ct)).PqcStage = PqcStage.Enforce;
        await scope.Db.SaveChangesAsync(ct);

        var preview = await scope.CreatePreviewService().PreviewApprovalAsync(created, "approver", ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.PqcOnly);
    }

    [Fact]
    public async Task UnlinkedTemplate_IsAdmittedWithNoPolicy()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var created = await scope.CreateRequestService().CreateAsync(WebServer("anything.anywhere"), "alice", ct);

        var preview = await scope.CreatePreviewService().PreviewApprovalAsync(created, "approver", ct);

        Assert.True(preview.Allowed);
        Assert.Null(preview.PolicyName);
        Assert.Null(preview.EvaluatedPolicyVersionNumber);
        Assert.False(preview.PolicyChangedSinceEvaluation);
    }

    [Fact]
    public async Task WritesNoRowChange()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var created = await scope.CreateRequestService().CreateAsync(WebServer("still.pending.example"), "alice", ct);
        var before = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);

        await scope.CreatePreviewService().PreviewApprovalAsync(created, "approver", ct);

        var after = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Pending, after.Status);
        Assert.Equal(before.UpdatedAtUtc, after.UpdatedAtUtc);
        Assert.Equal(before.PolicyVersionId, after.PolicyVersionId);
    }

    [Fact]
    public async Task NotPending_Throws()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var approved = new CertificateRequest { CommonName = "x.example", Type = "WebServer", Status = CertificateRequestStatus.Approved };

        await Assert.ThrowsAsync<ArgumentException>(
            () => scope.CreatePreviewService().PreviewApprovalAsync(approved, "approver", ct));
        Assert.Empty(scope.Audit.Entries);
    }
}
