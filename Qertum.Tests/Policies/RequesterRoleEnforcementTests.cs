using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class RequesterRoleEnforcementTests
{
    private const string Actor = "alice";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CertificateRequest WebServer(string cn) =>
        new() { CommonName = cn, RequestedBy = Actor, Type = "WebServer" };

    private static RequesterRoles Roles(params string[] roles) => RequesterRoles.From(roles);

    [Fact]
    public async Task Create_ByNonMember_IsRefused_AndWritesNoRow()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], name: "corp", ct: Ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(WebServer("a.example.com"), Actor, null, Roles("viewer"), Ct));

        Assert.Equal(PolicyRules.RequesterRole, Assert.Single(ex.Decision.Violations).Rule);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(r => r.CommonName == "a.example.com", Ct));
    }

    [Fact]
    public async Task Create_ByMember_IsAdmitted_AndTheAuditNamesTheRole()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], name: "corp", ct: Ct);

        var created = await scope.CreateRequestService().CreateAsync(WebServer("b.example.com"), Actor, null, Roles("OPS"), Ct);

        var entry = Assert.Single(scope.Audit.Entries, e => e.Action == "Created" && e.ResourceId == (Guid)created.Id);
        Assert.Equal("Requester role 'ops' admitted by policy 'corp' v1.", entry.Detail);
    }

    [Fact]
    public async Task Create_ByAdmin_IsAdmitted_AndTheAuditSaysBypassed()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], name: "corp", ct: Ct);

        var created = await scope.CreateRequestService().CreateAsync(WebServer("c.example.com"), Actor, null, Roles("admin"), Ct);

        Assert.Equal("Requester is admin; requester-role rule bypassed.",
            Assert.Single(scope.Audit.Entries, e => e.Action == "Created" && e.ResourceId == (Guid)created.Id).Detail);
    }

    [Fact]
    public async Task AcmeStyleCreate_WithNullRequester_IsAdmitted()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], ct: Ct);

        // The overload ACME finalize and EST use: no requester.
        var created = await scope.CreateRequestService().CreateAsync(WebServer("d.example.com"), "acme:1", "AcmeAutoApprove", Ct);

        Assert.NotEqual(default, created.Id);
        Assert.Null(Assert.Single(scope.Audit.Entries, e => e.Action == "Created").Detail);
    }

    [Fact]
    public async Task Renew_IsNotRoleChecked()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var original = await service.CreateAsync(WebServer("e.example.com"), Actor, Ct);
        original.Status = CertificateRequestStatus.Issued;
        await scope.Db.SaveChangesAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], ct: Ct);

        Assert.NotNull(await service.RenewAsync(original.Id, "auto-renewal", Ct));
    }

    [Fact]
    public async Task Approval_AfterTheRequesterLostTheRole_StillPasses()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], ct: Ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("f.example.com"), Actor, null, Roles("ops"), Ct);

        // Approval has no requester roles to check; the rule is submission-only.
        Assert.NotNull(await service.MarkAsApprovedAsync(created.Id, "approver", Ct));
    }

    [Fact]
    public async Task Update_ToARestrictedType_ByNonMember_IsRefused()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(new CertificateRequest
            { CommonName = "g.example.com", RequestedBy = Actor, Type = "ClientAuth" }, Actor, Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], ct: Ct);

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => service.UpdateAsync(created.Id,
            new CertificateRequest { CommonName = "g.example.com", Type = "WebServer", Status = CertificateRequestStatus.Pending },
            "bob", Roles("viewer"), Ct));
    }

    [Fact]
    public async Task CreatePreview_ByNonMember_IsRefusedWithTheViolation()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", requesterRoles: ["ops"], ct: Ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(
            new CertificateRequest { CommonName = "h.example.com", Type = "WebServer", Status = CertificateRequestStatus.Pending },
            Roles("viewer"), Ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.RequesterRole);
    }
}
