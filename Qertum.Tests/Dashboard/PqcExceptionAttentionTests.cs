using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Dashboard;

namespace Qertum.Tests.Dashboard;

public sealed class PqcExceptionAttentionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly DateTime Now = new(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);
    private static FakeTimeProvider Clock() => new(new DateTimeOffset(Now));

    private static PqcException Row(string template, DateTime expires, bool revoked = false) => new()
    {
        TemplateTypeKey = template, NamePattern = "secret.internal.example", Family = PqcExceptionFamily.Rsa,
        ExpiresAtUtc = expires, Reason = "legacy appliance", GrantedBy = "admin", CreatedAtUtc = Now.AddDays(-30),
        RevokedAtUtc = revoked ? Now.AddDays(-1) : null, RevokedBy = revoked ? "admin" : null
    };

    private static async Task<AttentionReport> ReportAsync(AttentionTestDb db, bool canEditSettings = true) =>
        await db.CreateService(Clock()).GetReportAsync(new AttentionAccess(true, canEditSettings), Ct);

    [Fact]
    public async Task OnlyActiveExceptionsEndingInsideTheWindow_AreReported()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.PqcExceptions.AddRange(
            Row("WebServer", Now.AddDays(3)),
            Row("ClientAuth", Now.AddDays(14)),              // boundary: inside
            Row("SMIME", Now.AddDays(15)),                   // outside
            Row("CodeSigning", Now.AddDays(-1)),             // already ended: no longer applies
            Row("WebServer", Now.AddDays(2), revoked: true)); // revoked: nothing to warn about
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.PqcExceptionExpiring);

        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Equal(2, item.Count);
        Assert.Equal(["WebServer", "ClientAuth"], item.Evidence.Select(e => e.Label).ToArray());
        Assert.Equal("/pqc-exceptions", item.ActionHref);
    }

    [Fact]
    public async Task EvidenceNeverCarriesTheNamePatternOrReason()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.PqcExceptions.Add(Row("WebServer", Now.AddDays(3)));
        await db.Db.SaveChangesAsync(Ct);

        var item = (await ReportAsync(db)).Items.Single(i => i.Kind == AttentionKind.PqcExceptionExpiring);

        var text = string.Join(' ', item.Evidence.Select(e => e.Label + e.Detail)) + item.Title + item.Explanation;
        Assert.DoesNotContain("secret.internal.example", text);
        Assert.DoesNotContain("legacy appliance", text);
    }

    [Fact]
    public async Task NothingEndingSoon_ReportsNothing()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.PqcExceptions.Add(Row("WebServer", Now.AddDays(90)));
        await db.Db.SaveChangesAsync(Ct);

        Assert.DoesNotContain((await ReportAsync(db)).Items, i => i.Kind == AttentionKind.PqcExceptionExpiring);
    }

    [Fact]
    public async Task WithoutSettingsEdit_TheCheckIsWithheldNotRun()
    {
        await using var db = await AttentionTestDb.CreateAsync(Ct);
        db.Db.PqcExceptions.Add(Row("WebServer", Now.AddDays(3)));
        await db.Db.SaveChangesAsync(Ct);

        var report = await ReportAsync(db, canEditSettings: false);

        Assert.Contains(AttentionKind.PqcExceptionExpiring, report.WithheldKinds);
        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.PqcExceptionExpiring);
    }
}
