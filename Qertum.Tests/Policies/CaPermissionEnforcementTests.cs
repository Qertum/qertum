using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CaPermissionEnforcementTests
{
    private const string Actor = "alice";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CallerContext Human(bool ca = false, bool admin = false) => new("sub-alice", Actor, admin, ca);
    private static CertificateRequest Sub(string cn) => new() { CommonName = cn, RequestedBy = Actor, RequestedBySubject = "sub-alice", Type = "SubordinateCA" };
    private static CertificateRequest Leaf(string cn) => new() { CommonName = cn, RequestedBy = Actor, RequestedBySubject = "sub-alice", Type = "WebServer" };

    [Fact]
    public async Task Create_ACaTemplate_WithoutThePermission_IsRefused_AndWritesNoRow()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(Sub("ca.example"), Actor, null, null, Human(), Ct));

        Assert.Equal(PolicyRules.CaPermission, Assert.Single(ex.Decision.Violations).Rule);
        Assert.Equal(PolicyEnforcementStage.Create, ex.Stage);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(Ct));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Create_ACaTemplate_WithPermissionOrAsAdmin_IsAdmitted(bool ca, bool admin)
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var created = await scope.CreateRequestService().CreateAsync(Sub("ca.example"), Actor, null, null, Human(ca, admin), Ct);

        Assert.Equal(CertificateRequestStatus.Pending, created.Status);
    }

    [Fact]
    public async Task Create_ALeafTemplate_NeverNeedsThePermission()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        Assert.NotEqual(default, (await scope.CreateRequestService().CreateAsync(Leaf("a.example"), Actor, null, null, Human(), Ct)).Id);
    }

    [Fact]
    public async Task Create_WithNoCaller_SkipsTheRule_ForInternalCallers()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        Assert.NotEqual(default, (await scope.CreateRequestService().CreateAsync(Sub("ca.example"), Actor, Ct)).Id);
    }

    [Fact]
    public async Task EnrollmentProtocols_NeverIssueACaTemplate()
    {
        // ACME/EST use the four-argument overload; a template key edited to SubordinateCA must still refuse.
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(Sub("ca.example"), "acme:1", "AcmeAutoApprove", Ct));

        Assert.Equal(PolicyRules.CaPermission, Assert.Single(ex.Decision.Violations).Rule);
        Assert.Contains("ACME", ex.Decision.Violations[0].Message);
    }

    [Fact]
    public async Task Update_RetypingALeafIntoACa_NeedsThePermission_ButTheReverseDoesNot()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var leaf = await service.CreateAsync(Leaf("a.example"), Actor, null, null, Human(), Ct);

        var retyped = Leaf("a.example");
        retyped.Type = "SubordinateCA";
        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            service.UpdateAsync(leaf.Id, retyped, Actor, null, Human(), Ct));

        var ca = await service.CreateAsync(Sub("ca.example"), Actor, null, null, Human(ca: true), Ct);
        var down = Sub("ca.example");
        down.Type = "WebServer";
        Assert.NotNull(await service.UpdateAsync(ca.Id, down, Actor, null, Human(), Ct));
    }

    [Fact]
    public async Task Renew_ACaCertificate_NeedsThePermission()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var ca = await service.CreateAsync(Sub("ca.example"), Actor, null, null, Human(ca: true), Ct);
        await scope.Db.CertificateRequests.Where(r => r.Id == ca.Id)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, CertificateRequestStatus.Issued), Ct);

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() => service.RenewAsync(ca.Id, Actor, Human(), Ct));
        Assert.NotNull(await service.RenewAsync(ca.Id, Actor, Human(ca: true), Ct));
    }

    [Fact]
    public async Task CreatePreview_ReportsTheRuleWithoutWriting()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(Sub("ca.example"), null, Human(), Ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.CaPermission);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(Ct));
    }
}
