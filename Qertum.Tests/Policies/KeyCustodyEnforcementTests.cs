using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class KeyCustodyEnforcementTests
{
    private const string Actor = "alice";
    private const string Csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----";
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CertificateRequest WebServer(string cn, string? csrPem = null) =>
        new() { CommonName = cn, RequestedBy = Actor, Type = "WebServer", CsrPem = csrPem };

    private static Task SeedAsync(PolicyTestDb scope, KeyCustodyMode custody) =>
        PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", keyCustody: custody, name: "custody", ct: Ct);

    [Fact]
    public async Task Create_WithoutACsr_IsRefused_AndWritesNoRow()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.CreateRequestService().CreateAsync(WebServer("a.example.com"), Actor, Ct));

        Assert.Equal(PolicyRules.KeyCustody, Assert.Single(ex.Decision.Violations).Rule);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(r => r.CommonName == "a.example.com", Ct));
    }

    [Fact]
    public async Task Create_CarryingACsr_IsAdmitted()
    {
        // The shape ACME finalize and EST enrollment submit: the requester generated the key.
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        var created = await scope.CreateRequestService()
            .CreateAsync(WebServer("b.example.com", Csr), "acme:1", "AcmeAutoApprove", Ct);

        Assert.NotEqual(default, created.Id);
    }

    [Fact]
    public async Task Create_UnderAnUnrestrictedPolicy_StillGeneratesTheKeyAtTheCa()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.Any);

        Assert.NotEqual(default, (await scope.CreateRequestService()
            .CreateAsync(WebServer("c.example.com"), Actor, Ct)).Id);
    }

    [Fact]
    public async Task Approval_OfARowPredatingTheRule_IsBlocked_AndLeavesItPending()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("d.example.com"), Actor, Ct);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            service.MarkAsApprovedAsync(created.Id, "approver", Ct));

        var stored = await scope.Db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, Ct);
        Assert.Equal(CertificateRequestStatus.Pending, stored.Status);
    }

    [Fact]
    public async Task ConsumerCheck_BeforeSigning_ReportsTheRule()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var created = await service.CreateAsync(WebServer("e.example.com"), Actor, Ct);
        var approved = await service.MarkAsApprovedAsync(created.Id, "approver", Ct);
        Assert.NotNull(approved);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        var decision = await service.CheckIssuancePolicyAsync(created.Id, Ct);

        Assert.False(decision.Allowed);
        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.KeyCustody);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(Csr)]
    public async Task Renew_IsRefused_BecauseARenewalAlwaysAsksTheCaToGenerateTheKey(string? sourceCsr)
    {
        // RenewAsync builds its row without CsrPem — deliberately, since reusing the submitted CSR
        // would reissue the same public key forever. So under this rule nothing renews, whichever
        // way the source was enrolled: the client re-enrolls over ACME or EST with a fresh CSR.
        // Auto-renewal never reaches this for CSR-issued certificates anyway —
        // GetCertsNeedingAutoRenewalAsync skips them, as the CA holds no key for them.
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var original = await service.CreateAsync(
            WebServer("f.example.com", sourceCsr), sourceCsr is null ? Actor : "acme:1", null, Ct);
        original.Status = CertificateRequestStatus.Issued;
        await scope.Db.SaveChangesAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        var ex = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            service.RenewAsync(original.Id, "auto-renewal", Ct));

        Assert.Equal(PolicyRules.KeyCustody, Assert.Single(ex.Decision.Violations).Rule);
    }

    [Fact]
    public async Task Renew_UnderAnUnrestrictedPolicy_IsUnaffected()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        var service = scope.CreateRequestService();
        var original = await service.CreateAsync(WebServer("g.example.com"), Actor, Ct);
        original.Status = CertificateRequestStatus.Issued;
        await scope.Db.SaveChangesAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.Any);

        Assert.NotNull(await service.RenewAsync(original.Id, "auto-renewal", Ct));
    }

    [Fact]
    public async Task CreatePreview_ReportsTheRule_WithoutWritingARow()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        await SeedAsync(scope, KeyCustodyMode.RequireClientGenerated);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(
            new CertificateRequest { CommonName = "h.example.com", Type = "WebServer", Status = CertificateRequestStatus.Pending },
            null, Ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.KeyCustody);
        Assert.False(await scope.Db.CertificateRequests.AnyAsync(r => r.CommonName == "h.example.com", Ct));
    }
}
