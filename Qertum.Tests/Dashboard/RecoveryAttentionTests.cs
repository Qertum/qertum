using Qertum.Services;
using Qertum.Services.Recovery;

namespace Qertum.Tests.Dashboard;

public sealed class RecoveryAttentionTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 6, 12, 0, 0, DateTimeKind.Utc);
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"recovery-attention-{Guid.NewGuid():N}");

    public RecoveryAttentionTests() => Directory.CreateDirectory(Path.Combine(_dir, "recovery"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static TimeProvider Clock => new FixedTimeProvider(new DateTimeOffset(Now));

    private IRecoveryStatusService Files => new FileBackedRecovery(_dir);

    private static string Stamp(DateTime utc) => utc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private void WriteBackup(DateTime completed) => File.WriteAllText(Path.Combine(_dir, "recovery", "last-backup.json"),
        $$"""{"schemaVersion":1,"completedAtUtc":"{{Stamp(completed)}}","archiveName":"qertum-backup-x.tar.gz","reportedBy":"backup.sh"}""");

    private sealed class FileBackedRecovery(string dir) : IRecoveryStatusService
    {
        public Task<RecoveryStatus> GetAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Evaluate(new CaSettings(), Now));

        public RecoveryStatus Evaluate(CaSettings settings, DateTime nowUtc) => RecoveryRecords.Evaluate(dir, settings, nowUtc);
    }

    private sealed class ThrowingRecovery : IRecoveryStatusService
    {
        public bool Called { get; private set; }

        public Task<RecoveryStatus> GetAsync(CancellationToken cancellationToken = default) => throw new InvalidOperationException();

        public RecoveryStatus Evaluate(CaSettings settings, DateTime nowUtc)
        {
            Called = true;
            throw new InvalidOperationException("boom");
        }
    }

    [Fact]
    public async Task AStaleBackup_IsOneWarning_WithTheAgeAndTheLimit()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        WriteBackup(Now.AddDays(-5));

        var report = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Equal(1, item.Count);
        Assert.Contains("5 days", item.Title);
        Assert.Contains("2 days", item.Title);
        Assert.Equal("/settings?section=system", item.ActionHref);
        Assert.Contains("qertum-backup-x.tar.gz", item.Evidence[0].Detail);
        Assert.Contains("not checked the archive", item.Explanation);
    }

    [Fact]
    public async Task AFreshBackup_AndNothingReported_ProduceNoItem_AndAreNotUnavailable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);

        var nothing = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);
        WriteBackup(Now.AddHours(-1));
        var fresh = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);

        Assert.DoesNotContain(nothing.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.DoesNotContain(fresh.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.DoesNotContain(AttentionKind.RecoveryStatus, nothing.UnavailableKinds);
    }

    [Fact]
    public async Task AnUnreadableRecord_IsAWarning_WithTheFixedProblemText()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        File.WriteAllText(Path.Combine(_dir, "recovery", "last-backup.json"), "garbage hunter2");

        var report = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.DoesNotContain("hunter2", System.Text.Json.JsonSerializer.Serialize(item));
    }

    [Fact]
    public async Task ABackupAndAVerifiedRestoreThatAreBothStale_AreOneItem_WithTwoPieces_OfEvidence()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        WriteBackup(Now.AddDays(-5));
        File.WriteAllText(Path.Combine(_dir, "recovery", "last-restore.json"),
            $$"""{"schemaVersion":1,"kind":"verified","completedAtUtc":"{{Stamp(Now.AddDays(-60))}}","archiveName":"x.tar.gz"}""");

        var report = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.Equal(2, item.Count);
        Assert.Equal(2, item.Evidence.Count);
        Assert.Contains("2 recovery checks", item.Title);
    }

    [Fact]
    public async Task ViewerOnly_WithholdsTheKind_AndNeverReadsTheFiles()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        var recovery = new ThrowingRecovery();

        var report = await scope.CreateService(Clock, recovery: recovery).GetReportAsync(AttentionAccessFor.ViewerOnly, ct);

        Assert.Contains(AttentionKind.RecoveryStatus, report.WithheldKinds);
        Assert.False(recovery.Called);
    }

    [Fact]
    public async Task AThrowingCheck_IsUnavailable_NotClear()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);

        var report = await scope.CreateService(Clock, recovery: new ThrowingRecovery()).GetReportAsync(AttentionAccessFor.Everything, ct);

        Assert.Contains(AttentionKind.RecoveryStatus, report.UnavailableKinds);
    }

    [Fact]
    public async Task WithoutARecoveryService_TheCheckIsSilent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.DoesNotContain(AttentionKind.RecoveryStatus, report.UnavailableKinds);
    }

    [Fact]
    public async Task AFailedRestoreTest_IsAWarning_NamingTheStepAndTheCheck_NoMatterHowOld()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        File.WriteAllText(Path.Combine(_dir, "recovery", "last-restore.json"),
            $$"""{"schemaVersion":1,"kind":"failed","completedAtUtc":"{{Stamp(Now.AddDays(-200))}}","archiveName":"qertum-backup-x.tar.gz","step":"usability","failedCheck":"key-ring","reportedBy":"restore-test.sh"}""");

        var report = await scope.CreateService(Clock, recovery: Files).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.RecoveryStatus);
        Assert.Equal(AttentionSeverity.Warning, item.Severity);
        Assert.Contains("key-ring", item.Title);
        Assert.Contains("usability", item.Evidence[0].Detail);
        Assert.Contains("qertum-backup-x.tar.gz", item.Evidence[0].Detail);
    }
}
