using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Tests.Policies;
using static Qertum.Tests.Pqc.PqcReportTestKit;

namespace Qertum.Tests.Pqc;

public sealed class PqcMigrationReportServiceTests
{
    private static CertificateRequestStatus Issued => CertificateRequestStatus.Issued;

    private static async Task<PqcMigrationReportResponse> ReportAsync(PolicyTestDb scope, PqcReportQuery? query = null,
        CancellationToken ct = default) =>
        await Service(scope.Db, Clock()).BuildAsync(query ?? new PqcReportQuery { PageSize = 500 }, ViewOnly, ct);

    private static PqcTemplateReport Web(PqcMigrationReportResponse report) =>
        Assert.Single(report.Templates, t => t.TypeKey == "WebServer");

    [Fact]
    public async Task LiveCertificates_SplitIntoTheStageBuckets()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("a.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)),
            Row("b.corp.example", CertificateKeyAlgorithm.EcdsaP256, Issued, Now.AddDays(30)),
            Row("c.corp.example", CertificateKeyAlgorithm.MlDsa65, Issued, Now.AddDays(30)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Warn, PageSize = 500 }, ct);

        var web = Web(report);
        Assert.Equal((3, 1, 0, 2, 0, 0), (web.LiveTotal, web.Compliant, web.ClassicalAllowed, web.ClassicalWarned,
            web.ClassicalRefused, web.ClassicalCoveredByException));
        Assert.Equal(PqcStage.Off, web.CurrentStage);
        Assert.Equal(PqcStage.Warn, web.ProposedStage);
        Assert.Equal(PqcStage.Warn, report.ProposedStage);
        Assert.Equal(PqcStage.Off, report.CaDefaultStage);
        // Compliant keys are counted, never listed.
        Assert.Equal(2, report.Items.TotalCount);
        Assert.DoesNotContain(report.Items.Items, i => i.CommonName == "c.corp.example");
    }

    [Theory]
    [InlineData(PqcStage.Off, 2, 0, 0)]
    [InlineData(PqcStage.Observe, 2, 0, 0)]
    [InlineData(PqcStage.Warn, 0, 2, 0)]
    [InlineData(PqcStage.Pilot, 0, 2, 0)]      // live certificates are judged as renewals, which Pilot allows with a warning
    [InlineData(PqcStage.Enforce, 0, 0, 2)]
    public async Task EachStage_PutsLiveClassicalCertificatesInTheRightBucket(PqcStage stage, int allowed, int warned, int refused)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("a.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)),
            Row("b.corp.example", CertificateKeyAlgorithm.EcdsaP384, Issued, Now.AddDays(30)));
        await scope.Db.SaveChangesAsync(ct);

        var web = Web(await ReportAsync(scope, new PqcReportQuery { ProposedStage = stage, PageSize = 500 }, ct));

        Assert.Equal((allowed, warned, refused), (web.ClassicalAllowed, web.ClassicalWarned, web.ClassicalRefused));
    }

    [Fact]
    public async Task ExpiredRevokedAndPendingRevocation_AreOneNotAffectedCount_ThatReconcilesWithTheInventory()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("live.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)),
            Row("expired.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(-1)),
            Row("revoked.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Revoked, Now.AddDays(30)),
            Row("revoking.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.PendingRevocation, Now.AddDays(30)),
            Row("rejected.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Rejected));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, ct: ct);

        var web = Web(report);
        Assert.Equal((1, 3), (web.LiveTotal, web.NotAffected));
        var inventory = await new CertificateInventoryService(scope.Db).GetAsync(1, 500, ct);
        Assert.Equal(inventory.TotalCount, web.LiveTotal + web.NotAffected);   // holds while no request is paired
        Assert.DoesNotContain(report.Items.Items, i => i.CommonName is "rejected.corp.example" or "expired.corp.example");
    }

    [Fact]
    public async Task InFlightRequests_AreCountedAndListed_AsAtApproval()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var original = Row("orig.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30));
        scope.Db.CertificateRequests.Add(original);
        await scope.Db.SaveChangesAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("pending.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending),
            Row("approved.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Approved),
            Row("renewing.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending, renewedFrom: original.Id),
            Row("processing.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Processing));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Pilot, PageSize = 500 }, ct);

        Assert.Equal(3, Web(report).InFlight);
        var byName = report.Items.Items.Where(i => i.InFlight).ToDictionary(i => i.CommonName);
        Assert.Equal(PqcVerdictKind.Refused, byName["pending.corp.example"].Verdict);    // new request at Pilot
        Assert.Equal(PqcVerdictKind.Refused, byName["approved.corp.example"].Verdict);
        Assert.Equal(PqcVerdictKind.Warned, byName["renewing.corp.example"].Verdict);    // RenewedFromId makes it a renewal
        Assert.True(byName["renewing.corp.example"].IsRenewal);
        Assert.False(byName["pending.corp.example"].IsRenewal);
        Assert.DoesNotContain("processing.corp.example", byName.Keys);
    }

    [Fact]
    public async Task ANullStoredAlgorithm_IsJudgedAsRsaAndFlaggedAssumed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(Row("old.corp.example", algorithm: null, Issued, Now.AddDays(30)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Enforce, PageSize = 500 }, ct);

        var item = Assert.Single(report.Items.Items);
        Assert.True(item.AlgorithmAssumed);
        Assert.Equal("RSA", item.KeyAlgorithm);
        Assert.Equal(PqcVerdictKind.Refused, item.Verdict);
        var web = Web(report);
        Assert.Equal((1, 1), (web.AlgorithmAssumed, web.ClassicalRefused));
    }

    [Fact]
    public async Task AnActiveException_IsCountedSeparately_AndNamedOnTheItem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("covered.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)),
            Row("other.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)));
        var exception = new PqcException
        {
            TemplateTypeKey = "WebServer", NamePattern = "covered.corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(10), Reason = "legacy", GrantedBy = "admin", CreatedAtUtc = Now
        };
        scope.Db.PqcExceptions.Add(exception);
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Enforce, PageSize = 500 }, ct);

        var web = Web(report);
        Assert.Equal((1, 1), (web.ClassicalCoveredByException, web.ClassicalRefused));
        var covered = Assert.Single(report.Items.Items, i => i.Verdict == PqcVerdictKind.CoveredByException);
        Assert.Equal("covered.corp.example", covered.CommonName);
        Assert.Equal(exception.Id, covered.ExceptionId);
        Assert.Null(Assert.Single(report.Items.Items, i => i.Verdict == PqcVerdictKind.Refused).ExceptionId);
    }

    [Fact]
    public async Task AProposedStage_OverridesEveryTemplate_WhileCurrentStagesStayTruthful()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        (await scope.Db.CertificateTemplates.FirstAsync(t => t.TypeKey == "ClientAuth", ct)).PqcStageOverride = PqcStage.Enforce;
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Warn, PageSize = 500 }, ct);

        var client = Assert.Single(report.Templates, t => t.TypeKey == "ClientAuth");
        Assert.Equal((PqcStage.Enforce, PqcStage.Warn), (client.CurrentStage, client.ProposedStage));
        var web = Web(report);
        Assert.Equal((PqcStage.Off, PqcStage.Warn), (web.CurrentStage, web.ProposedStage));
    }

    [Fact]
    public async Task WithoutAProposal_ProposedEqualsCurrent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var report = await ReportAsync(scope, ct: ct);

        Assert.Null(report.ProposedStage);
        Assert.All(report.Templates, t => Assert.Equal(t.CurrentStage, t.ProposedStage));
    }

    [Fact]
    public async Task ATemplateFilter_LimitsTheScope_AndAnUnknownTemplateIs404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("web.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30), type: "WebServer"),
            Row("dev.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30), type: "ClientAuth"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { TemplateTypeKey = "ClientAuth", PageSize = 500 }, ct);

        Assert.Equal("ClientAuth", Assert.Single(report.Templates).TypeKey);
        Assert.Equal("dev.corp.example", Assert.Single(report.Items.Items).CommonName);
        await Assert.ThrowsAsync<NotFoundException>(() =>
            Service(scope.Db, Clock()).BuildAsync(new PqcReportQuery { TemplateTypeKey = "NoSuchTemplate" }, ViewOnly, ct));
    }

    [Fact]
    public async Task ATemplatelessTypeTheReportLists_CanBeUsedAsTheFilter()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(
            Row("old.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30), type: "DeletedTemplate"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { TemplateTypeKey = "DeletedTemplate", PageSize = 500 }, ct);

        Assert.Equal("DeletedTemplate", Assert.Single(report.Templates).TypeKey);
        Assert.Equal("old.corp.example", Assert.Single(report.Items.Items).CommonName);
    }

    [Fact]
    public async Task ARowWithoutATemplate_GetsItsOwnEntry_AndARootCaRequestUsesTheDefaultStage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(Row("Root", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(300), type: "RootCA"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Enforce, PageSize = 500 }, ct);

        var root = Assert.Single(report.Templates, t => t.TypeKey == "RootCA");
        Assert.Equal("(no template)", root.Name);
        Assert.Equal((PqcStage.Off, 1), (root.CurrentStage, root.LiveTotal));
        Assert.Equal(PqcVerdictKind.Refused, Assert.Single(report.Items.Items).Verdict);
    }

    [Fact]
    public async Task ItemsAreOrderedRefusedFirstThenBySoonestExpiry_AndPageCorrectly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Row("late.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(90)),
            Row("soon.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(5)),
            Row("mid.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(40)));
        await scope.Db.SaveChangesAsync(ct);
        var query = new PqcReportQuery { ProposedStage = PqcStage.Enforce, PageSize = 2 };

        var first = await ReportAsync(scope, query, ct);
        var second = await ReportAsync(scope, query.WithPage(2, 2), ct);
        var beyond = await ReportAsync(scope, query.WithPage(9, 2), ct);

        Assert.Equal(["soon.corp.example", "mid.corp.example"], first.Items.Items.Select(i => i.CommonName));
        Assert.Equal(["late.corp.example"], second.Items.Items.Select(i => i.CommonName));
        Assert.Empty(beyond.Items.Items);
        Assert.Equal(3, beyond.Items.TotalCount);
    }

    [Fact]
    public async Task OnlyTheReturnedPageCarriesInventoryFacts_AndAMalformedPemStaysVisible()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var broken = Row("broken.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(5));
        broken.CertificatePem = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----";
        scope.Db.CertificateRequests.AddRange(broken,
            Row("pending.corp.example", CertificateKeyAlgorithm.Rsa, CertificateRequestStatus.Pending));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, ct: ct);

        var live = Assert.Single(report.Items.Items, i => !i.InFlight);
        var facts = Assert.Single(live.Certificates);
        Assert.Equal("InvalidCertificate", facts.AnalysisStatus);
        Assert.Equal("Unknown", facts.SubjectKeyAlgorithm);
        Assert.Empty(Assert.Single(report.Items.Items, i => i.InFlight).Certificates);
    }

    [Fact]
    public async Task AnEmptyPopulation_IsAnEmptyReport()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var report = await ReportAsync(scope, ct: ct);

        Assert.Empty(report.Items.Items);
        Assert.Equal(0, report.Items.TotalCount);
        Assert.All(report.Templates, t => Assert.Equal((0, 0, 0), (t.LiveTotal, t.InFlight, t.NotAffected)));
    }

    [Fact]
    public async Task NoSettingsRow_ReportsEnforceAsTheDefault_AndInsertsNoRow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct, seedSettings: false);
        scope.Db.CertificateRequests.Add(Row("a.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await ReportAsync(scope, ct: ct);

        Assert.Equal(PqcStage.Enforce, report.CaDefaultStage);
        Assert.Equal(PqcStage.Enforce, Web(report).CurrentStage);
        Assert.Equal(PqcVerdictKind.Refused, Assert.Single(report.Items.Items).Verdict);   // a renewal would be refused at Enforce
        Assert.False(await scope.Db.Settings.AnyAsync(ct));
    }

    [Fact]
    public async Task TheReport_WritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(Row("a.corp.example", CertificateKeyAlgorithm.Rsa, Issued, Now.AddDays(30)));
        await scope.Db.SaveChangesAsync(ct);
        var before = (await scope.Db.CertificateRequests.CountAsync(ct), await scope.Db.LifecycleEvents.CountAsync(ct),
            await scope.Db.WebhookDeliveries.CountAsync(ct), await scope.Db.Settings.CountAsync(ct));

        await ReportAsync(scope, new PqcReportQuery { ProposedStage = PqcStage.Enforce, PageSize = 500 }, ct);

        Assert.Equal(before, (await scope.Db.CertificateRequests.CountAsync(ct), await scope.Db.LifecycleEvents.CountAsync(ct),
            await scope.Db.WebhookDeliveries.CountAsync(ct), await scope.Db.Settings.CountAsync(ct)));
        Assert.Empty(scope.Audit.Entries);
    }
}
