using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CertificateRequestPolicyEnforcementTests
{
    private const string Actor = "alice";

    private static CertificateRequest WebServer(string cn) =>
        new() { CommonName = cn, RequestedBy = Actor, Type = "WebServer" };

    [Fact]
    public async Task Create_OutsidePolicy_ThrowsWritesNoRowAndAudits()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(
            () => service.CreateAsync(WebServer("host.other.net"), Actor, ct));

        Assert.Equal(PolicyEnforcementStage.Create, ex.Stage);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(r => r.CommonName == "host.other.net", ct));
        Assert.Contains(scope.Audit.Entries, e => e.Action == "PolicyRejected" && e.ResourceName == "host.other.net");
    }

    [Fact]
    public async Task Create_Allowed_RecordsPolicyVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var version = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);

        var created = await scope.CreateRequestService().CreateAsync(WebServer("host.corp.example.com"), Actor, ct);

        Assert.Equal(version.Id, created.PolicyVersionId);
        Assert.NotNull(created.PolicyEvaluatedAtUtc);
    }

    [Fact]
    public async Task Create_UnlinkedTemplate_RecordsNoVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var created = await scope.CreateRequestService().CreateAsync(WebServer("anything.anywhere"), Actor, ct);

        Assert.Null(created.PolicyVersionId);
        Assert.Null(created.PolicyEvaluatedAtUtc);
    }

    [Fact]
    public async Task Renew_IsEvaluatedAgainstCurrentPublishedVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();
        var original = await service.CreateAsync(WebServer("host.corp.example.com"), Actor, ct);
        var row = await scope.Db.CertificateRequests.SingleAsync(r => r.Id == original.Id, ct);
        row.Status = CertificateRequestStatus.Issued;
        await scope.Db.SaveChangesAsync(ct);

        await PublishNewVersionAsync(scope, v1, ["other.com"], ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(
            () => service.RenewAsync(original.Id, Actor, ct));
        Assert.Equal(PolicyEnforcementStage.Renew, ex.Stage);
        Assert.Equal(2, ex.Decision.VersionNumber);
        Assert.Equal(1, await scope.Db.CertificateRequests.CountAsync(ct));
    }

    [Fact]
    public async Task Update_TypeSwitch_AppliesTheNewTemplatesPolicy()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "ClientAuth", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.other.net"), Actor, ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => service.UpdateAsync(created.Id,
            new CertificateRequest
            {
                CommonName = "host.other.net",
                Type = "ClientAuth",
                PropertiesJson = "{}",
                Status = CertificateRequestStatus.Pending
            }, Actor, ct));

        Assert.Equal(PolicyEnforcementStage.Update, ex.Stage);
        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal("WebServer", stored.Type);
    }

    [Fact]
    public async Task Approve_Blocked_LeavesRequestPendingAndAudits()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.other.net"), Actor, ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(
            () => service.MarkAsApprovedAsync(created.Id, "approver", ct));

        Assert.Equal(PolicyEnforcementStage.Approval, ex.Stage);
        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Pending, stored.Status);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "ApprovalBlockedByPolicy" && e.ResourceId == (Guid)created.Id);
        Assert.DoesNotContain(scope.Audit.Entries, e => e.Action == "Approved");
    }

    [Fact]
    public async Task Approve_Allowed_RecordsVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var version = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), Actor, ct);

        var approved = await service.MarkAsApprovedAsync(created.Id, "approver", ct);

        Assert.NotNull(approved);
        Assert.Equal(CertificateRequestStatus.Approved, approved.Status);
        Assert.Equal(version.Id, approved.PolicyVersionId);
    }

    [Fact]
    public async Task IssuanceCheck_PolicyTightenedAfterApproval_RejectsWithReason()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), Actor, ct);
        await service.MarkAsApprovedAsync(created.Id, "approver", ct);
        await PublishNewVersionAsync(scope, v1, ["other.com"], ct);
        var claimed = await service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(claimed);

        var decision = await service.CheckIssuancePolicyAsync(claimed.Id, ct);

        Assert.False(decision.Allowed);
        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Rejected, stored.Status);
        Assert.Contains("issuance policy", stored.FailureReason, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "PolicyRejected" && e.PerformedBy == "queue-consumer");
    }

    [Fact]
    public async Task IssuanceCheck_Allowed_RecordsTheVersionInForceAtSigning()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), Actor, ct);
        await service.MarkAsApprovedAsync(created.Id, "approver", ct);
        await PublishNewVersionAsync(scope, v1, ["corp.example.com"], ct);
        var v2 = await scope.Db.IssuancePolicyVersions.AsNoTracking()
            .SingleAsync(v => v.Status == IssuancePolicyVersionStatus.Published, ct);
        var claimed = await service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(claimed);

        var decision = await service.CheckIssuancePolicyAsync(claimed.Id, ct);

        Assert.True(decision.Allowed);
        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(v2.Id, stored.PolicyVersionId);
        Assert.Equal(CertificateRequestStatus.Processing, stored.Status);
    }

    internal static async Task PublishNewVersionAsync(PolicyTestDb scope, IssuancePolicyVersion current,
        string[] dnsSuffixes, CancellationToken ct)
    {
        var tracked = await scope.Db.IssuancePolicyVersions.SingleAsync(v => v.Id == current.Id, ct);
        tracked.Status = IssuancePolicyVersionStatus.Superseded;
        await scope.Db.SaveChangesAsync(ct);
        scope.Db.IssuancePolicyVersions.Add(new IssuancePolicyVersion
        {
            PolicyId = tracked.PolicyId,
            VersionNumber = tracked.VersionNumber + 1,
            Status = IssuancePolicyVersionStatus.Published,
            AllowedDnsSuffixesJson = JsonSerializer.Serialize(dnsSuffixes),
            CreatedBy = "test",
            PublishedBy = "test",
            PublishedAtUtc = DateTime.UtcNow
        });
        await scope.Db.SaveChangesAsync(ct);
    }
}
