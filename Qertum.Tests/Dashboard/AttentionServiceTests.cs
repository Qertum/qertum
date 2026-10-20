using Qertum.Services;

namespace Qertum.Tests.Dashboard;

public sealed partial class AttentionServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);
    private static readonly FixedTimeProvider Clock = new(Now);
    private static DateTime NowUtc => Now.UtcDateTime;

    private static CertificateRequest Request(string cn, CertificateRequestStatus status,
        DateTime createdAtUtc, DateTime? updatedAtUtc = null, string? failureReason = null) => new()
    {
        CommonName = cn,
        RequestedBy = "alice",
        Type = "WebServer",
        Status = status,
        CreatedAtUtc = createdAtUtc,
        UpdatedAtUtc = updatedAtUtc ?? createdAtUtc,
        FailureReason = failureReason
    };

    // ── AgingApprovals ──

    [Fact]
    public async Task AgingApprovals_IncludesOnlyPendingOlderThanTheThreshold()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Request("old.example.com", CertificateRequestStatus.Pending, NowUtc.AddHours(-73)),
            Request("fresh.example.com", CertificateRequestStatus.Pending, NowUtc.AddHours(-71)),
            Request("approved.example.com", CertificateRequestStatus.Approved, NowUtc.AddHours(-100)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.AgingApprovals);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Equal(1, item.Count);
        var evidence = Assert.Single(item.Evidence);
        Assert.Equal("old.example.com", evidence.Label);
        Assert.StartsWith("/certificate-requests/", evidence.Href);
        Assert.Contains("3 days", item.Title);
    }

    [Fact]
    public async Task AgingApprovals_CapsEvidenceAtFiveOldestFirstButCountsAll()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        for (var i = 0; i < 7; i++)
            scope.Db.CertificateRequests.Add(
                Request($"host{i}.example.com", CertificateRequestStatus.Pending, NowUtc.AddDays(-10 + i)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.AgingApprovals);
        Assert.Equal(7, item.Count);
        Assert.Equal(5, item.Evidence.Count);
        Assert.Equal("host0.example.com", item.Evidence[0].Label);
    }

    [Fact]
    public async Task AgingApprovals_TitleFollowsTheConfiguredThreshold()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        scope.Db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, Id = 1, AttentionPendingApprovalAgeHours = 5 });
        scope.Db.CertificateRequests.Add(Request("a.example.com", CertificateRequestStatus.Pending, NowUtc.AddHours(-6)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.AgingApprovals);
        Assert.Contains("5 hours", item.Title);
    }

    // ── FailedIssuance ──

    [Fact]
    public async Task FailedIssuance_IncludesPipelineRejectionsInsideTheWindowOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.AddRange(
            Request("failed.example.com", CertificateRequestStatus.Rejected, NowUtc.AddDays(-2),
                updatedAtUtc: NowUtc.AddDays(-1), failureReason: "CA key unavailable"),
            Request("denied.example.com", CertificateRequestStatus.Rejected, NowUtc.AddDays(-2),
                updatedAtUtc: NowUtc.AddDays(-1), failureReason: null),
            Request("ancient.example.com", CertificateRequestStatus.Rejected, NowUtc.AddDays(-30),
                updatedAtUtc: NowUtc.AddDays(-8), failureReason: "old failure"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.FailedIssuance);
        Assert.Equal(1, item.Count);
        var evidence = Assert.Single(item.Evidence);
        Assert.Equal("failed.example.com", evidence.Label);
        Assert.Equal("CA key unavailable", evidence.Detail);
        Assert.Contains("7 days", item.Title);
        Assert.Equal("/denied", item.ActionHref);
    }

    // ── Report shape and permissions ──

    [Fact]
    public async Task EmptyDatabase_ReportsNothingAndWithholdsNothingForAnAdmin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        Assert.Empty(report.Items);
        Assert.Empty(report.WithheldKinds);
        Assert.Empty(report.UnavailableKinds);
        Assert.Equal(NowUtc, report.GeneratedAtUtc);
    }

    [Fact]
    public async Task NoPermissions_WithholdsEveryKindAndReportsNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        scope.Db.CertificateRequests.Add(Request("old.example.com", CertificateRequestStatus.Pending, NowUtc.AddDays(-10)));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Nothing, ct);

        Assert.Empty(report.Items);
        Assert.Equal(Enum.GetValues<AttentionKind>(), report.WithheldKinds);
    }
}
