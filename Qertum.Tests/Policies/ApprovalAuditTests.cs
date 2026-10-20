using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class ApprovalAuditTests
{
    private static CertificateRequest WebServer(string cn) =>
        new() { CommonName = cn, RequestedBy = "alice", Type = "WebServer" };

    [Fact]
    public async Task Approved_RecordsPolicyVersionAndReportedPreview()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), "alice", ct);

        await service.MarkAsApprovedAsync(created.Id, "approver", new ApprovalPreviewReport(v1.Id, true), ct);

        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "Approved");
        Assert.Equal("approver", entry.PerformedBy);
        Assert.Contains("Approved under policy", entry.Detail);
        Assert.Contains("v1 (same version as its last evaluation)", entry.Detail);
        Assert.Contains("reported a preview of policy 'Web servers' v1 that admitted it.", entry.Detail);
    }

    [Fact]
    public async Task Approved_WithoutReport_SaysSo()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("plain.example"), "alice", ct);

        await service.MarkAsApprovedAsync(created.Id, "approver", ct);

        Assert.Equal("Approved under no issuance policy. The approver's client reported no preview.",
            Assert.Single(scope.Audit.Entries, e => e.Action == "Approved").Detail);
    }

    [Fact]
    public async Task Approved_UnknownReportedVersion_DoesNotCallItNoPolicyOrClaimAChange()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        var unknownId = Guid.NewGuid();

        await service.MarkAsApprovedAsync(created.Id, "approver", new ApprovalPreviewReport(unknownId, true), ct);

        var detail = Assert.Single(scope.Audit.Entries, e => e.Action == "Approved").Detail;
        Assert.Contains($"unrecognized policy version id {unknownId}", detail);
        Assert.DoesNotContain("preview of no policy", detail);
        Assert.DoesNotContain("governing version changed to", detail);
    }

    [Fact]
    public async Task Approved_AfterRepublish_SaysThePreviewWasOfAnOlderVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        await CertificateRequestPolicyEnforcementTests.PublishNewVersionAsync(scope, v1, ["corp.example.com"], ct);

        await service.MarkAsApprovedAsync(created.Id, "approver", new ApprovalPreviewReport(v1.Id, true), ct);

        Assert.Contains("reported a preview of policy 'Web servers' v1 that admitted it; the governing version changed to policy 'Web servers' v2 before approval.",
            Assert.Single(scope.Audit.Entries, e => e.Action == "Approved").Detail);
    }

    [Fact]
    public async Task Approved_AfterAnUpdate_DoesNotClaimTheCreationVersion()
    {
        // UpdateAsync re-evaluates and overwrites PolicyVersionId, so the stored version is the last
        // evaluation's, not the creation's; the immutable Approved entry must not say "at creation".
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var v1 = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.corp.example.com"), "alice", ct);
        await CertificateRequestPolicyEnforcementTests.PublishNewVersionAsync(scope, v1, ["corp.example.com"], ct);
        await service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = "host.corp.example.com", Type = "WebServer", PropertiesJson = "{}", Status = CertificateRequestStatus.Pending
        }, "alice", ct);

        await service.MarkAsApprovedAsync(created.Id, "approver", ct);

        var detail = Assert.Single(scope.Audit.Entries, e => e.Action == "Approved").Detail;
        Assert.DoesNotContain("at creation", detail);
        Assert.Contains("v2 (same version as its last evaluation)", detail);
    }

    [Fact]
    public async Task Blocked_RecordsViolationsAndReport()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("host.other.net"), "alice", ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(
            () => service.MarkAsApprovedAsync(created.Id, "approver", new ApprovalPreviewReport(null, true), ct));

        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "ApprovalBlockedByPolicy");
        Assert.StartsWith("Approval refused by policy", entry.Detail);
        Assert.Contains("(no policy version was recorded when it was last evaluated)", entry.Detail);
        Assert.Contains("reported a preview of no policy that admitted it; the governing version changed to policy 'Web servers' v1 before approval.", entry.Detail);
    }

    [Fact]
    public async Task AutoApprovedInsert_WritesAnApprovedEntryNamingTheSetting()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var request = WebServer("auto.example");
        request.Status = CertificateRequestStatus.Approved;

        var created = await scope.CreateRequestService().CreateAsync(request, "acme:account-1", "AcmeAutoApprove", ct);

        Assert.Equal(["Created", "Approved"], scope.Audit.Entries.Select(e => e.Action));
        var approved = scope.Audit.Entries[1];
        Assert.Equal("acme:account-1", approved.PerformedBy);
        Assert.Equal((Guid)created.Id, approved.ResourceId);
        Assert.Equal("Auto-approved at creation by AcmeAutoApprove under no issuance policy.", approved.Detail);
    }

    [Fact]
    public async Task AutoRenewalApproval_NamesTheSettingWithoutClaimingAClientPreview()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var request = new CertificateRequest
        {
            CommonName = "auto-renew.example", RequestedBy = "alice", Type = "WebServer",
            RenewedFromId = new CertificateRequestId(Guid.NewGuid())
        };
        var created = await service.CreateAsync(request, "auto-renewal", ct);

        await service.MarkAsAutoApprovedAsync(created.Id, "auto-renewal", "AutoRenewalAutoApprove", ct);

        var detail = Assert.Single(scope.Audit.Entries, e => e.Action == "Approved").Detail;
        Assert.Equal("Auto-approved by AutoRenewalAutoApprove under no issuance policy.", detail);
    }

    [Fact]
    public async Task BlockedAutoRenewal_NamesTheSettingWithoutClaimingAClientPreview()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("auto-renew.other.net"), "auto-renewal", ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "Web servers", ct: ct);

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            service.MarkAsAutoApprovedAsync(created.Id, "auto-renewal", "AutoRenewalAutoApprove", ct));

        var detail = Assert.Single(scope.Audit.Entries, e => e.Action == "ApprovalBlockedByPolicy").Detail;
        Assert.Contains("AutoRenewalAutoApprove", detail);
        Assert.DoesNotContain("approver's client", detail);
    }

    [Fact]
    public async Task PendingInsert_WritesNoApprovedEntry()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        await scope.CreateRequestService().CreateAsync(WebServer("manual.example"), "alice", "AcmeAutoApprove", ct);

        Assert.DoesNotContain(scope.Audit.Entries, e => e.Action == "Approved");
    }
}
