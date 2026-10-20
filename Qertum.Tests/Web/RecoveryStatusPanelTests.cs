using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Dashboard;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class RecoveryStatusPanelTests
{
    private static readonly DateTime Now = new(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);

    private static RecoveryStatus Status(RecoveryItem backup, RecoveryItem? restore = null) => new()
    {
        GeneratedAtUtc = Now,
        Backup = backup,
        Restore = restore ?? new RecoveryItem { State = RecoveryItemState.NotReported }
    };

    private static IRenderedComponent<RecoveryStatusPanel> Render(BunitContext context, RecoveryStatus? status, bool unavailable = false) =>
        context.Render<RecoveryStatusPanel>(p => p.Add(x => x.Status, status).Add(x => x.Unavailable, unavailable));

    [Fact]
    public void AFreshBackup_ShowsItsAge_AndTheReportedNotVerifiedCaption()
    {
        using var context = new BunitContext();
        var cut = Render(context, Status(new RecoveryItem
        {
            State = RecoveryItemState.Fresh, CompletedAtUtc = Now.AddHours(-5), ArchiveName = "qertum-backup-x.tar.gz",
            ReportedBy = "backup.sh", ThresholdHours = 48
        }));

        var row = cut.Find("[data-test='recovery-backup']");
        Assert.Contains("5 hours ago", row.TextContent);
        Assert.Contains("qertum-backup-x.tar.gz", row.TextContent);
        Assert.NotEmpty(row.QuerySelectorAll(".badge-success"));
        Assert.Contains("has not verified", cut.Find("[data-test='recovery-caption']").TextContent);
    }

    [Fact]
    public void ANotReportedBackup_IsNeutral_NotAWarning()
    {
        using var context = new BunitContext();
        var cut = Render(context, Status(new RecoveryItem { State = RecoveryItemState.NotReported }));

        var row = cut.Find("[data-test='recovery-backup']");
        Assert.Contains("Not reported", row.TextContent);
        Assert.Empty(row.QuerySelectorAll(".badge-warning, .badge-danger"));
    }

    [Fact]
    public void AStaleBackup_IsAWarning_AndAnUnreadableOneShowsItsProblem()
    {
        using var context = new BunitContext();
        var stale = Render(context, Status(new RecoveryItem
        {
            State = RecoveryItemState.Stale, CompletedAtUtc = Now.AddDays(-5), ThresholdHours = 48
        }));
        Assert.NotEmpty(stale.Find("[data-test='recovery-backup']").QuerySelectorAll(".badge-warning"));
        Assert.Contains("5 days ago", stale.Find("[data-test='recovery-backup']").TextContent);

        var unreadable = Render(context, Status(new RecoveryItem { State = RecoveryItemState.Unreadable, Problem = "The file is not valid JSON." }));
        Assert.NotEmpty(unreadable.Find("[data-test='recovery-backup']").QuerySelectorAll(".badge-danger"));
        Assert.Contains("The file is not valid JSON.", unreadable.Find("[data-test='recovery-backup']").TextContent);
    }

    [Fact]
    public void ARestorePerformed_IsLabelledNotVerified()
    {
        using var context = new BunitContext();
        var cut = Render(context, Status(
            new RecoveryItem { State = RecoveryItemState.NotReported },
            new RecoveryItem { State = RecoveryItemState.NotJudged, Kind = "performed", CompletedAtUtc = Now.AddDays(-3), ReportedBy = "restore.sh" }));

        var row = cut.Find("[data-test='recovery-restore']");
        Assert.Contains("performed", row.TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not verified", row.TextContent);
        Assert.Empty(row.QuerySelectorAll(".badge-success"));
    }

    [Fact]
    public void WhenTheLoadFailed_ItSaysUnavailable_NotAllClear()
    {
        using var context = new BunitContext();
        var cut = Render(context, null, unavailable: true);

        Assert.Contains("unavailable", cut.Find("[data-test='recovery-unavailable']").TextContent);
        Assert.Empty(cut.FindAll("[data-test='recovery-backup']"));
    }

    [Fact]
    public void TheSettingsSystemTab_ShowsTheThresholdFields_AndThePanel()
    {
        using var context = SettingsPageHarness.NewContext(admin: true);
        var cut = context.Render<Settings>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-system")));
        cut.Find("#settings-tab-system").Click();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='recovery-status']")));
        Assert.NotNull(cut.Find("#attention-backup-age"));
        Assert.NotNull(cut.Find("#attention-restore-age"));
        Assert.Contains("Not reported", cut.Find("[data-test='recovery-backup']").TextContent);
    }

    [Fact]
    public void TheSettingsPage_StillLoads_WhenOnlyTheRecoveryStatusFails()
    {
        using var context = SettingsPageHarness.NewContext(admin: true, recoveryStatusFails: true);
        var cut = context.Render<Settings>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-system")));
        cut.Find("#settings-tab-system").Click();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='recovery-unavailable']")));
    }

    [Fact]
    public void AFailedRestoreTest_IsADangerBadge_NamingTheCheck_AndAUsableOneSaysBootedOffline()
    {
        using var context = new BunitContext();
        var failed = Render(context, Status(new RecoveryItem { State = RecoveryItemState.NotReported }, new RecoveryItem
        {
            State = RecoveryItemState.Failed, Kind = "failed", Step = "usability", FailedCheck = "key-ring",
            CompletedAtUtc = Now.AddHours(-3), ArchiveName = "qertum-backup-x.tar.gz"
        }));

        var row = failed.Find("[data-test='recovery-restore']");
        Assert.Contains("Failed", row.TextContent);
        Assert.Contains("key-ring", row.TextContent);
        Assert.NotEmpty(row.QuerySelectorAll(".badge-danger"));

        using var second = new BunitContext();
        var usable = Render(second, Status(new RecoveryItem { State = RecoveryItemState.NotReported }, new RecoveryItem
        {
            State = RecoveryItemState.Fresh, Kind = "usable", CompletedAtUtc = Now.AddHours(-3), ThresholdHours = 840
        }));
        Assert.Contains("booted offline", usable.Find("[data-test='recovery-restore']").TextContent);
    }
}
