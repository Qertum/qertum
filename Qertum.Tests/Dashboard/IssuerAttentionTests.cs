using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Dashboard;
using Qertum.Services.Issuers;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Dashboard;

public sealed class IssuerAttentionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTime Now = new(2026, 9, 27, 12, 0, 0, DateTimeKind.Utc);
    private static FakeTimeProvider Clock() => new(new DateTimeOffset(Now));

    private static Issuer Row(string name, IssuerStatus status = IssuerStatus.Active, IssuerKeyCustody custody = IssuerKeyCustody.Online,
        DateTime? validTo = null, IssuerId? parent = null)
    {
        var row = IssuerModelTests.Row(name, status: status);
        row.KeyCustody = custody;
        row.ValidTo = validTo ?? Now.AddYears(5);
        row.ParentIssuerId = parent;
        row.Kind = parent is null ? IssuerKind.Root : IssuerKind.Intermediate;
        return row;
    }

    private static async Task<AttentionReport> ReportAsync(AttentionTestDb db, bool canEditSettings = true) =>
        await db.CreateService(Clock()).GetReportAsync(new AttentionAccess(true, canEditSettings), Ct);

    [Fact]
    public async Task IssuerExpiringWithin90Days_IsAWarning_AndExpiredIsCritical()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.Issuers.AddRange(Row("Soon", validTo: Now.AddDays(60)), Row("Gone", status: IssuerStatus.Retired, validTo: Now.AddDays(-1)),
            Row("Fine", validTo: Now.AddDays(400)));
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.IssuerExpiring);

        Assert.Equal(AttentionSeverity.Critical, item.Severity);
        Assert.Equal(2, item.Count);
        Assert.Equal("/issuers", item.ActionHref);
    }

    [Fact]
    public async Task IssuerExpiringOnlySoon_IsAWarning()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.Issuers.Add(Row("Soon", validTo: Now.AddDays(60)));
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.IssuerExpiring);

        Assert.Equal(AttentionSeverity.Warning, item.Severity);
    }

    [Fact]
    public async Task OfflineRootWithoutUploadedCrl_UnderAnActiveIntermediate_IsCritical()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        var root = Row("Offline Root", custody: IssuerKeyCustody.Offline);
        db.Db.Issuers.AddRange(root, Row("Issuing", parent: root.Id));
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.RootCrlExpiring);

        Assert.Equal(AttentionSeverity.Critical, item.Severity);
    }

    [Fact]
    public async Task OfflineRootWithoutAnActiveChild_IsNotReported()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.Issuers.Add(Row("Lonely Offline Root", custody: IssuerKeyCustody.Offline));
        await db.Db.SaveChangesAsync(Ct);

        Assert.DoesNotContain((await ReportAsync(db)).Items, i => i.Kind == AttentionKind.RootCrlExpiring);
    }

    [Fact]
    public async Task UploadedCrlNextUpdateWithin30Days_IsAWarning()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        var root = Row("Offline Root", custody: IssuerKeyCustody.Offline);
        root.UploadedCrlDer = [0x30, 0x00];
        root.UploadedCrlNumber = 3;
        root.UploadedCrlNextUpdateUtc = Now.AddDays(10);
        db.Db.Issuers.AddRange(root, Row("Issuing", parent: root.Id));
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.RootCrlExpiring);

        Assert.Equal(AttentionSeverity.Warning, item.Severity);
    }

    [Fact]
    public async Task RetiredIssuerWithNothingValid_IsArchivable_ButNotWithAValidCertificate()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        var empty = Row("Empty", status: IssuerStatus.Retired);
        var busy = Row("Busy", status: IssuerStatus.Retired);
        db.Db.Issuers.AddRange(empty, busy);
        db.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "b.example", RequestedBy = "seed", Status = CertificateRequestStatus.Issued,
            CertificatePem = "pem", ValidTo = Now.AddDays(30), IssuerId = busy.Id
        });
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.IssuerArchivable);

        Assert.Equal("Empty", Assert.Single(item.Evidence).Label);
    }

    [Fact]
    public async Task IssuerRevokedOnItsParentsCrl_IsCritical()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        var rootKeys = CaCertificateBuilderTests.Root();
        var root = Row("Offline Root", custody: IssuerKeyCustody.Offline);
        var child = Row("Revoked Issuing", status: IssuerStatus.Retired, parent: root.Id);
        child.SerialNumber = "0ABC";
        child.RetiredAtUtc = Now.AddHours(-1);
        var other = Row("Merely Retired", status: IssuerStatus.Retired, parent: root.Id);
        other.SerialNumber = "0DEF";
        other.RetiredAtUtc = Now.AddHours(-1);
        root.UploadedCrlDer = CaCertificateBuilder.BuildCrl(new LocalKeyPairCaSigner(rootKeys.Key), rootKeys.Cert,
            [new OfflineRevocation("0ABC", Now.AddHours(-2), "keyCompromise")], 1, Now.AddHours(-2), Now.AddDays(90));
        root.UploadedCrlNextUpdateUtc = Now.AddDays(90);
        db.Db.Issuers.AddRange(root, child, other);
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.IssuerRevoked);

        Assert.Equal(AttentionSeverity.Critical, item.Severity);
        Assert.Equal("Revoked Issuing", Assert.Single(item.Evidence).Label);
    }

    [Fact]
    public async Task IssuerKinds_AreWithheldWithoutSettingsEdit()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);

        var report = await ReportAsync(db, canEditSettings: false);

        Assert.Contains(AttentionKind.IssuerExpiring, report.WithheldKinds);
        Assert.Contains(AttentionKind.RootCrlExpiring, report.WithheldKinds);
        Assert.Contains(AttentionKind.IssuerArchivable, report.WithheldKinds);
        Assert.Contains(AttentionKind.IssuerRevoked, report.WithheldKinds);
    }
}
