#pragma warning disable xUnit1051 // the lambdas under test are the service calls; cancellation is not what these tests probe
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Pqc;

public sealed class PqcEnforcementSitesTests
{
    private const string Actor = "test-user";

    private static async Task WithStage(PqcStage stage, Func<CertificateRequestDbContext, ICertificateRequestService, Task> body)
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        await TestServices.SetStageAsync(db, stage);
        await body(db, TestServices.CreateRequestService(db));
    }

    private static CertificateRequest Rsa(string cn = "app.corp.example") =>
        new() { CommonName = cn, RequestedBy = "alice", KeyAlgorithm = CertificateKeyAlgorithm.Rsa };

    [Fact]
    public async Task Create_AtEnforce_IsRefused() =>
        await WithStage(PqcStage.Enforce, async (_, s) =>
            await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.CreateAsync(Rsa(), Actor)));

    [Fact]
    public async Task Create_AtWarn_SucceedsAndCarriesAWarning() =>
        await WithStage(PqcStage.Warn, async (_, s) =>
        {
            var created = await s.CreateAsync(Rsa(), Actor);
            var warning = Assert.Single(created.Warnings!);
            Assert.Contains("classical", warning);
        });

    [Fact]
    public async Task Create_AtOff_HasNoWarnings() =>
        await WithStage(PqcStage.Off, async (_, s) =>
            Assert.Null((await s.CreateAsync(Rsa(), Actor)).Warnings));

    [Fact]
    public async Task Update_ToClassical_AtEnforce_IsRefused() =>
        await WithStage(PqcStage.Off, async (db, s) =>
        {
            var created = await s.CreateAsync(new CertificateRequest
            { CommonName = "u.corp.example", RequestedBy = "a", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65 }, Actor);
            await TestServices.SetStageAsync(db, PqcStage.Enforce);
            await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.UpdateAsync(created.Id,
                new CertificateRequest { CommonName = "u.corp.example", RequestedBy = "a", KeyAlgorithm = CertificateKeyAlgorithm.Rsa }, Actor));
        });

    [Fact]
    public async Task Renew_AtPilot_IsAllowedWithAWarning_ButANewRequestIsRefused() =>
        await WithStage(PqcStage.Off, async (db, s) =>
        {
            var original = await IssuedClassicalAsync(db, s, "renew.corp.example");
            await TestServices.SetStageAsync(db, PqcStage.Pilot);

            var renewal = await s.RenewAsync(original.Id, Actor);
            Assert.NotNull(renewal!.Warnings);
            await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.CreateAsync(Rsa("brand-new.corp.example"), Actor));
        });

    [Fact]
    public async Task Renew_AtEnforce_IsRefused() =>
        await WithStage(PqcStage.Off, async (db, s) =>
        {
            var original = await IssuedClassicalAsync(db, s, "renew2.corp.example");
            await TestServices.SetStageAsync(db, PqcStage.Enforce);
            var ex = await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.RenewAsync(original.Id, Actor));
            Assert.Contains("Submit a new request", ex.Message);
        });

    [Fact]
    public async Task Approve_AfterTheStageTightened_Answers422StageAndKeepsTheRequestPending() =>
        await WithStage(PqcStage.Off, async (db, s) =>
        {
            var created = await s.CreateAsync(Rsa("approve.corp.example"), Actor);
            await TestServices.SetStageAsync(db, PqcStage.Enforce);

            var ex = await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.MarkAsApprovedAsync(created.Id, Actor));
            Assert.Equal(PolicyEnforcementStage.Approval, ex.Stage);
            Assert.Equal(CertificateRequestStatus.Pending,
                (await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id)).Status);
        });

    [Fact]
    public async Task Consumer_RejectsAnApprovedClassicalRequest_WhenTheStageTightened() =>
        await WithStage(PqcStage.Off, async (db, s) =>
        {
            var created = await s.CreateAsync(Rsa("consume.corp.example"), Actor);
            await s.MarkAsApprovedAsync(created.Id, Actor);
            await TestServices.SetStageAsync(db, PqcStage.Enforce);
            // The consumer only checks rows it has claimed; the reject path needs Processing.
            Assert.NotNull(await s.DequeueNextApprovedAsync());

            var decision = await s.CheckIssuancePolicyAsync(created.Id);

            Assert.False(decision.Allowed);
            var row = await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id);
            Assert.Equal(CertificateRequestStatus.Rejected, row.Status);
            Assert.Contains("PQC", row.FailureReason);
        });

    [Fact]
    public async Task Create_WithAnActiveException_IsAllowedWithAWarning() =>
        await WithStage(PqcStage.Enforce, async (db, s) =>
        {
            var now = TimeProvider.System.GetUtcNow().UtcDateTime;
            db.PqcExceptions.Add(new PqcException
            {
                TemplateTypeKey = "WebServer", NamePattern = "legacy.corp.example", Family = PqcExceptionFamily.Rsa,
                ExpiresAtUtc = now.AddDays(30), Reason = "old LB", GrantedBy = "admin", CreatedAtUtc = now
            });
            await db.SaveChangesAsync();

            var created = await s.CreateAsync(Rsa("legacy.corp.example"), Actor);
            Assert.NotNull(created.Warnings);
            await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.CreateAsync(Rsa("other.corp.example"), Actor));
        });

    [Fact]
    public async Task Create_WithAnExceptionCoveringOneNameButAnExtraDnsSan_IsStillRefused() =>
        await WithStage(PqcStage.Enforce, async (db, s) =>
        {
            var now = TimeProvider.System.GetUtcNow().UtcDateTime;
            db.PqcExceptions.Add(new PqcException
            {
                TemplateTypeKey = "WebServer", NamePattern = "legacy.corp.example", Family = PqcExceptionFamily.Rsa,
                ExpiresAtUtc = now.AddDays(30), Reason = "old LB", GrantedBy = "admin", CreatedAtUtc = now
            });
            await db.SaveChangesAsync();

            var request = Rsa("legacy.corp.example");
            request.PropertiesJson = "{\"DnsNames\":[\"legacy.corp.example\",\"extra.other.example\"]}";
            await Assert.ThrowsAsync<PqcPolicyViolationException>(() => s.CreateAsync(request, Actor));
        });

    [Fact]
    public async Task Create_WithRenewedFromId_AtPilot_IsTreatedAsARenewal() =>
        await WithStage(PqcStage.Pilot, async (_, s) =>
        {
            // ACME finalize and EST reenroll reach CreateAsync with the back-pointer set.
            var repeat = new CertificateRequest
            {
                CommonName = "repeat.corp.example", RequestedBy = "alice", KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
                RenewedFromId = Guid.NewGuid()
            };

            var created = await s.CreateAsync(repeat, Actor);

            Assert.NotNull(created.Warnings);
        });

    private static async Task<CertificateRequest> IssuedClassicalAsync(CertificateRequestDbContext db, ICertificateRequestService s, string cn)
    {
        var created = await s.CreateAsync(Rsa(cn), Actor);
        var row = await db.CertificateRequests.SingleAsync(r => r.Id == created.Id);
        row.Status = CertificateRequestStatus.Issued;
        row.ValidTo = TimeProvider.System.GetUtcNow().UtcDateTime.AddDays(10);
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        return row;
    }
}
