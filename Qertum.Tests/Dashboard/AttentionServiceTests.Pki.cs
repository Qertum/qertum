using Qertum.Services;

namespace Qertum.Tests.Dashboard;

public sealed partial class AttentionServiceTests
{
    private static async Task<AttentionReport> ReportWithSettingsAsync(
        CaSettings settings, CancellationToken ct, ICertificateGenerator? generator = null)
    {
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        settings.Id = 1;
        scope.Db.Settings.Add(settings);
        await scope.Db.SaveChangesAsync(ct);
        return await scope.CreateService(Clock, generator).GetReportAsync(AttentionAccessFor.Everything, ct);
    }

    // ── DeltaCrlBase ── (CrlValidityHours 24, DeltaCrlValidityHours 6 in every case below)

    [Fact]
    public async Task DeltaCrlBase_AbsentWhenDeltaCrlsAreDisabled()
    {
        var report = await ReportWithSettingsAsync(new CaSettings
        {
            DeltaCrlEnabled = false, BaseCrlThisUpdateUtc = NowUtc.AddDays(-10)
        }, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.DeltaCrlBase);
    }

    [Fact]
    public async Task DeltaCrlBase_WarnsWhenNoBaseWasEverPublished()
    {
        var report = await ReportWithSettingsAsync(new CaSettings
        {
            DeltaCrlEnabled = true, BaseCrlThisUpdateUtc = null
        }, TestContext.Current.CancellationToken);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.DeltaCrlBase);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
    }

    [Fact]
    public async Task DeltaCrlBase_AbsentWhileMoreThanOneDeltaLifetimeRemains()
    {
        var report = await ReportWithSettingsAsync(new CaSettings
        {
            DeltaCrlEnabled = true, CrlValidityHours = 24, DeltaCrlValidityHours = 6,
            BaseCrlNumber = 4, BaseCrlThisUpdateUtc = NowUtc.AddHours(-17) // lapses in 7h
        }, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.DeltaCrlBase);
    }

    [Fact]
    public async Task DeltaCrlBase_WarnsWithinOneDeltaLifetimeOfLapsing()
    {
        var report = await ReportWithSettingsAsync(new CaSettings
        {
            DeltaCrlEnabled = true, CrlValidityHours = 24, DeltaCrlValidityHours = 6,
            BaseCrlNumber = 4, BaseCrlThisUpdateUtc = NowUtc.AddHours(-19) // lapses in 5h
        }, TestContext.Current.CancellationToken);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.DeltaCrlBase);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Contains("CRL #4", Assert.Single(item.Evidence).Label);
    }

    [Fact]
    public async Task DeltaCrlBase_IsCriticalOnceLapsed()
    {
        var report = await ReportWithSettingsAsync(new CaSettings
        {
            DeltaCrlEnabled = true, CrlValidityHours = 24, DeltaCrlValidityHours = 6,
            BaseCrlNumber = 4, BaseCrlThisUpdateUtc = NowUtc.AddHours(-25)
        }, TestContext.Current.CancellationToken);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.DeltaCrlBase);
        Assert.Equal(AttentionSeverity.Critical, item.Severity);
        Assert.Equal(item, report.Items[0]); // Critical sorts first
    }

    // ── CaExpiry ── (ExpiringSoonDays 30)

    private static ICertificateGenerator Ca(DateTime? validTo, bool initialized = true) =>
        StubCertificateGenerator.Returning(new CaStatusResponse
        {
            IsInitialized = initialized, ValidTo = validTo, SubjectDn = "CN=Test Root"
        });

    [Fact]
    public async Task CaExpiry_AbsentWhenCaIsNotInitialized()
    {
        var report = await ReportWithSettingsAsync(new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 },
            TestContext.Current.CancellationToken, Ca(NowUtc.AddDays(-1), initialized: false));

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.CaExpiry);
    }

    [Fact]
    public async Task CaExpiry_AbsentOutsideTheExpiringSoonWindow()
    {
        var report = await ReportWithSettingsAsync(new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 },
            TestContext.Current.CancellationToken, Ca(NowUtc.AddDays(31)));

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.CaExpiry);
    }

    [Fact]
    public async Task CaExpiry_WarnsInsideTheExpiringSoonWindow()
    {
        var report = await ReportWithSettingsAsync(new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 },
            TestContext.Current.CancellationToken, Ca(NowUtc.AddDays(10)));

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.CaExpiry);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Contains("10 days", item.Title);
        Assert.Equal("CN=Test Root", Assert.Single(item.Evidence).Label);
    }

    [Fact]
    public async Task CaExpiry_IsCriticalOnceExpired()
    {
        var report = await ReportWithSettingsAsync(new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 },
            TestContext.Current.CancellationToken, Ca(NowUtc.AddDays(-1)));

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.CaExpiry);
        Assert.Equal(AttentionSeverity.Critical, item.Severity);
    }

    [Fact]
    public async Task ThrowingCheck_IsUnavailableAndTheRestOfTheReportSurvives()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(Request("old.example.com", CertificateRequestStatus.Pending, NowUtc.AddDays(-10)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock, StubCertificateGenerator.Throwing())
            .GetReportAsync(AttentionAccessFor.Everything, ct);

        Assert.Equal([AttentionKind.CaExpiry], report.UnavailableKinds);
        Assert.Contains(report.Items, i => i.Kind == AttentionKind.AgingApprovals);
    }

    [Fact]
    public async Task ViewerOnly_WithholdsExactlyTheSettingsKinds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.ViewerOnly, ct);

        Assert.Equal(
            [AttentionKind.FailedWebhookDeliveries, AttentionKind.DeltaCrlBase, AttentionKind.CaExpiry,
             AttentionKind.IssuerExpiring, AttentionKind.RootCrlExpiring, AttentionKind.IssuerArchivable, AttentionKind.IssuerRevoked,
             AttentionKind.PqcExceptionExpiring, AttentionKind.RecoveryStatus,
             AttentionKind.ApprovalsWaiting /* administrators only */],
            report.WithheldKinds);
    }
}
