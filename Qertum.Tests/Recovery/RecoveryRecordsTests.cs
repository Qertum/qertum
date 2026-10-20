using Qertum.Services;
using Qertum.Services.Recovery;

namespace Qertum.Tests.Recovery;

public sealed class RecoveryRecordsTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"recovery-records-{Guid.NewGuid():N}");

    public RecoveryRecordsTests() => Directory.CreateDirectory(Path.Combine(_dir, "recovery"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private void Write(string name, string text) => File.WriteAllText(Path.Combine(_dir, "recovery", name), text);

    private RecoveryStatus Evaluate(CaSettings? settings = null) =>
        RecoveryRecords.Evaluate(_dir, settings ?? new CaSettings(), Now);

    private static string Stamp(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static string Backup(DateTime completed) =>
        $$"""{"schemaVersion":1,"completedAtUtc":"{{Stamp(completed)}}","archiveName":"qertum-backup-20261006T100000Z.tar.gz","sizeBytes":1234,"reportedBy":"backup.sh"}""";

    private static string Restore(DateTime completed, string kind) =>
        $$"""{"schemaVersion":1,"kind":"{{kind}}","completedAtUtc":"{{Stamp(completed)}}","archiveName":"qertum-backup-20261006T100000Z.tar.gz","reportedBy":"restore.sh"}""";

    [Fact]
    public void NoDirectoryAtAll_IsNotReported_ForBoth()
    {
        Directory.Delete(Path.Combine(_dir, "recovery"));

        var status = Evaluate();

        Assert.Equal(RecoveryItemState.NotReported, status.Backup.State);
        Assert.Equal(RecoveryItemState.NotReported, status.Restore.State);
        Assert.Equal(Now, status.GeneratedAtUtc);
    }

    [Fact]
    public void AFreshBackup_CarriesItsReportedFields()
    {
        Write("last-backup.json", Backup(Now.AddHours(-2)));

        var item = Evaluate().Backup;

        Assert.Equal(RecoveryItemState.Fresh, item.State);
        Assert.Equal(Now.AddHours(-2), item.CompletedAtUtc);
        Assert.Equal("qertum-backup-20261006T100000Z.tar.gz", item.ArchiveName);
        Assert.Equal(1234, item.SizeBytes);
        Assert.Equal("backup.sh", item.ReportedBy);
        Assert.Equal(48, item.ThresholdHours);
        Assert.Null(item.Problem);
    }

    [Fact]
    public void ABackupExactlyAtTheLimit_IsFresh_AndOneSecondOverIsStale()
    {
        Write("last-backup.json", Backup(Now.AddHours(-48)));
        Assert.Equal(RecoveryItemState.Fresh, Evaluate().Backup.State);

        Write("last-backup.json", Backup(Now.AddHours(-48).AddSeconds(-1)));
        Assert.Equal(RecoveryItemState.Stale, Evaluate().Backup.State);
    }

    [Fact]
    public void TheLimitComesFromSettings()
    {
        Write("last-backup.json", Backup(Now.AddHours(-2)));

        var item = Evaluate(new CaSettings { AttentionBackupMaxAgeHours = 1 }).Backup;

        Assert.Equal(RecoveryItemState.Stale, item.State);
        Assert.Equal(1, item.ThresholdHours);
    }

    [Theory]
    [InlineData("not json at all")]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("""{"schemaVersion":2,"completedAtUtc":"2026-10-06T10:00:00Z"}""")]
    [InlineData("""{"schemaVersion":"1","completedAtUtc":"2026-10-06T10:00:00Z"}""")]
    [InlineData("""{"schemaVersion":1}""")]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"yesterday"}""")]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00+02:00"}""")]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00Z","sizeBytes":-5}""")]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00Z","archiveName":"bad\u0007name"}""")]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00Z","reportedBy":7}""")]
    public void AMalformedRecord_IsUnreadable_NeverFresh(string text)
    {
        Write("last-backup.json", text);

        var item = Evaluate().Backup;

        Assert.Equal(RecoveryItemState.Unreadable, item.State);
        Assert.NotNull(item.Problem);
        Assert.Null(item.CompletedAtUtc);
    }

    [Fact]
    public void ATruncatedFile_IsUnreadable()
    {
        var whole = Backup(Now.AddHours(-2));
        Write("last-backup.json", whole[..(whole.Length / 2)]);

        Assert.Equal(RecoveryItemState.Unreadable, Evaluate().Backup.State);
    }

    [Fact]
    public void AnOversizeFile_IsUnreadable()
    {
        Write("last-backup.json", Backup(Now.AddHours(-2)) + new string(' ', RecoveryRecords.MaxFileBytes));

        var item = Evaluate().Backup;

        Assert.Equal(RecoveryItemState.Unreadable, item.State);
        Assert.Contains("4 KiB", item.Problem);
    }

    [Fact]
    public void AFileThatIsADirectory_IsUnreadable_NotAnException()
    {
        Directory.CreateDirectory(Path.Combine(_dir, "recovery", "last-backup.json"));

        Assert.Equal(RecoveryItemState.Unreadable, Evaluate().Backup.State);
    }

    [Fact]
    public void ATimestampMoreThanFiveMinutesAhead_IsUnreadable_ButFourMinutesIsFine()
    {
        Write("last-backup.json", Backup(Now.AddMinutes(6)));
        Assert.Equal(RecoveryItemState.Unreadable, Evaluate().Backup.State);

        Write("last-backup.json", Backup(Now.AddMinutes(4)));
        Assert.Equal(RecoveryItemState.Fresh, Evaluate().Backup.State);
    }

    [Fact]
    public void AnUnreadableRecord_NeverEchoesFileContent()
    {
        Write("last-backup.json", """{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00Z","archiveName":"bad\u0007","secret":"hunter2"}""");

        var item = Evaluate().Backup;

        Assert.Equal(RecoveryItemState.Unreadable, item.State);
        Assert.DoesNotContain("hunter2", System.Text.Json.JsonSerializer.Serialize(item));
    }

    [Fact]
    public void ARestorePerformed_IsShownButNeverJudged_EvenWhenOld()
    {
        Write("last-restore.json", Restore(Now.AddDays(-400), "performed"));

        var item = Evaluate().Restore;

        Assert.Equal(RecoveryItemState.NotJudged, item.State);
        Assert.Equal("performed", item.Kind);
        Assert.Equal(Now.AddDays(-400), item.CompletedAtUtc);
        Assert.Null(item.ThresholdHours);
    }

    [Fact]
    public void ARestoreVerified_IsJudgedAgainstTheDayLimit()
    {
        Write("last-restore.json", Restore(Now.AddDays(-34), "verified"));
        Assert.Equal(RecoveryItemState.Fresh, Evaluate().Restore.State);

        Write("last-restore.json", Restore(Now.AddDays(-36), "verified"));
        var item = Evaluate().Restore;

        Assert.Equal(RecoveryItemState.Stale, item.State);
        Assert.Equal(35 * 24, item.ThresholdHours);
    }

    [Theory]
    [InlineData("""{"schemaVersion":1,"completedAtUtc":"2026-10-06T10:00:00Z"}""")]
    [InlineData("""{"schemaVersion":1,"kind":"other","completedAtUtc":"2026-10-06T10:00:00Z"}""")]
    public void ARestoreWithoutAKnownKind_IsUnreadable(string text)
    {
        Write("last-restore.json", text);

        Assert.Equal(RecoveryItemState.Unreadable, Evaluate().Restore.State);
    }

    [Fact]
    public void TheTwoFilesAreIndependent()
    {
        Write("last-backup.json", Backup(Now.AddHours(-2)));
        Write("last-restore.json", "garbage");

        var status = Evaluate();

        Assert.Equal(RecoveryItemState.Fresh, status.Backup.State);
        Assert.Equal(RecoveryItemState.Unreadable, status.Restore.State);
    }
    private static string Failed(DateTime completed, string step = "usability", string check = "key-ring") =>
        $$"""{"schemaVersion":1,"kind":"failed","completedAtUtc":"{{Stamp(completed)}}","archiveName":"qertum-backup-20261006T100000Z.tar.gz","step":"{{step}}","failedCheck":"{{check}}","reportedBy":"restore-test.sh"}""";

    [Fact]
    public void AUsableRestore_IsJudgedLikeAVerifiedOne()
    {
        Write("last-restore.json", Restore(Now.AddDays(-10), "usable"));
        var fresh = Evaluate().Restore;
        Assert.Equal(RecoveryItemState.Fresh, fresh.State);
        Assert.Equal("usable", fresh.Kind);
        Assert.Equal(35 * 24, fresh.ThresholdHours);

        Write("last-restore.json", Restore(Now.AddDays(-36), "usable"));
        Assert.Equal(RecoveryItemState.Stale, Evaluate().Restore.State);
    }

    [Fact]
    public void AFailedRestore_IsFailed_NeverStale_AndCarriesItsStepAndCheck()
    {
        Write("last-restore.json", Failed(Now.AddDays(-200)));

        var item = Evaluate().Restore;

        Assert.Equal(RecoveryItemState.Failed, item.State);
        Assert.Equal("failed", item.Kind);
        Assert.Equal("usability", item.Step);
        Assert.Equal("key-ring", item.FailedCheck);
        Assert.Null(item.ThresholdHours);
    }

    [Theory]
    [InlineData("other", "key-ring")]
    [InlineData("usability", "")]
    [InlineData("usability", "bad value")]
    [InlineData("usability", "has;semicolon")]
    public void AFailedRestore_WithABadStepOrCheck_IsUnreadable(string step, string check)
    {
        Write("last-restore.json", Failed(Now.AddHours(-1), step, check));

        var item = Evaluate().Restore;

        Assert.Equal(RecoveryItemState.Unreadable, item.State);
        Assert.Null(item.FailedCheck);
    }

    [Fact]
    public void AFailedRestore_WithNoStepOrCheck_IsUnreadable()
    {
        Write("last-restore.json", Restore(Now.AddHours(-1), "failed"));

        Assert.Equal(RecoveryItemState.Unreadable, Evaluate().Restore.State);
    }
}
