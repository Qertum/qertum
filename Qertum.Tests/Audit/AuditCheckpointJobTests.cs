using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Audit;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Serilog;
using Serilog.Formatting.Compact;

namespace Qertum.Tests.Audit;

public sealed class AuditCheckpointJobTests : IDisposable
{
    private readonly string _data = Path.Combine(Path.GetTempPath(), "audit-job-" + Guid.NewGuid().ToString("N"));
    private string Pattern => Path.Combine(_data, "audit-logs", "audit-.clef");

    public AuditCheckpointJobTests() => Directory.CreateDirectory(Path.Combine(_data, "audit-logs"));

    public void Dispose()
    {
        try { Directory.Delete(_data, recursive: true); } catch { /* best effort */ }
    }

    private AuditCheckpointJobHandler Handler(NoticeTestHost.RecordingWebhooks webhooks) => new(
        new AuditCheckpointReader(Options.Create(new AuditLogOptions { File = { Path = Pattern } }),
            new SecretStorageOptions { DataDirectory = _data }, new FakeTimeProvider()),
        webhooks);

    [Fact]
    public async Task WithChainedEntries_OneAuditCheckpointEventIsEnqueued_WithTheHeads()
    {
        using (var log = new LoggerConfiguration().WriteTo.File(new CompactJsonFormatter(), Pattern, shared: true).CreateLogger())
        {
            var chain = new AuditChain("api", []);
            chain.Write(log, "A", "x");
            chain.Write(log, "B", "x");
        }

        var webhooks = new NoticeTestHost.RecordingWebhooks();
        var result = await Handler(webhooks).HandleAsync(new BackgroundJob(), TestContext.Current.CancellationToken);

        var sent = Assert.Single(webhooks.Events);
        Assert.Equal(WellKnownWebhookEvents.AuditCheckpoint, sent.EventType);
        Assert.Equal("1", sent.Fields!["chainCount"]);
        Assert.Contains("\"writer\":\"api\"", sent.Fields["heads"]);
        Assert.Contains("\"seq\":2", sent.Fields["heads"]);
        Assert.NotNull(sent.Fields["generatedAt"]);
        Assert.Contains("1", result);
    }

    [Fact]
    public async Task WithNothingChained_NothingIsSent_AndTheJobSaysSkipped()
    {
        var webhooks = new NoticeTestHost.RecordingWebhooks();

        var result = await Handler(webhooks).HandleAsync(new BackgroundJob(), TestContext.Current.CancellationToken);

        Assert.Empty(webhooks.Events);
        Assert.StartsWith("skipped", result);
    }

    [Fact]
    public void TheSchedule_FollowsTheOptions_AndIsOffWhenDisabled()
    {
        var on = AuditCheckpointJobHandler.Schedule(new AuditLogOptions.CheckpointOptions { IntervalMinutes = 15 });
        var off = AuditCheckpointJobHandler.Schedule(new AuditLogOptions.CheckpointOptions { Enabled = false });

        Assert.Equal(TimeSpan.FromMinutes(15), on.Interval);
        Assert.True(on.Enabled);
        Assert.False(off.Enabled);
        Assert.Equal(WellKnownJobTypes.AuditCheckpoint, on.JobType);
    }
}
