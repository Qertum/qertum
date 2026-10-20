using Microsoft.EntityFrameworkCore;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class LifecycleEventSinkTests
{
    [Fact]
    public async Task OneAuditCall_WritesTheFileLineAndATableRowWithTheSameId()
    {
        var ct = TestContext.Current.CancellationToken;
        using var harness = new AuditLogHarness();
        var requestId = Guid.NewGuid();

        await harness.Service.LogAsync("Approved", "alice", requestId, "web.example.com", "ok", ct);
        harness.Flush();

        var line = Assert.Single(harness.AuditFileLines());
        await using var db = harness.Database.CreateContext();
        var row = await db.LifecycleEvents.SingleAsync(ct);
        Assert.Contains(row.Id.ToString(), line, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(LifecycleEventKinds.Audit, row.Kind);
        Assert.Equal(LifecycleSubjectTypes.CertificateRequest, row.SubjectType);
        Assert.Equal(requestId, row.SubjectId);
        Assert.Equal("Approved", row.Action);
        Assert.Equal("alice", row.PerformedBy);
        Assert.Equal("ok", row.Detail);
    }

    [Fact]
    public async Task AnAuditEventWithNoResource_IsWrittenToTheFileOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        using var harness = new AuditLogHarness();

        await harness.Service.LogAsync("SettingsUpdated", "alice", cancellationToken: ct);
        harness.Flush();

        Assert.Single(harness.AuditFileLines());
        await using var db = harness.Database.CreateContext();
        Assert.Equal(0, await db.LifecycleEvents.CountAsync(ct));
    }

    [Fact]
    public async Task ABrokenTable_NeitherFailsTheCallNorStopsTheFileLine()
    {
        // The file is the record. A table problem must stay inside Serilog's batching.
        var ct = TestContext.Current.CancellationToken;
        using var harness = new AuditLogHarness();
        await using (var db = harness.Database.CreateContext())
            await db.Database.ExecuteSqlRawAsync("DROP TABLE LifecycleEvents", ct);

        // Completes without throwing, although the table insert will fail.
        await harness.Service.LogAsync("Approved", "alice", Guid.NewGuid(), cancellationToken: ct);

        // Read before any flush: the file line must not depend on the table's batch succeeding.
        Assert.Single(harness.AuditFileLines());
    }

    [Fact]
    public async Task ARowAlreadyPresent_IsNotInsertedTwice()
    {
        // A batch retried after a commit whose acknowledgement was lost must not duplicate rows.
        var ct = TestContext.Current.CancellationToken;
        using var harness = new AuditLogHarness();
        var sink = new LifecycleEventTableSink(harness.Database.CreateScopeFactory());
        var logEvent = AuditLogEvent("Approved", Guid.NewGuid());

        await sink.EmitBatchAsync([logEvent]);
        await sink.EmitBatchAsync([logEvent]);

        await using var db = harness.Database.CreateContext();
        Assert.Equal(1, await db.LifecycleEvents.CountAsync(ct));
    }

    private static Serilog.Events.LogEvent AuditLogEvent(string action, Guid resourceId) => new(
        DateTimeOffset.UtcNow, Serilog.Events.LogEventLevel.Information, null,
        new Serilog.Parsing.MessageTemplateParser().Parse("Audit {Action}"),
        [
            new Serilog.Events.LogEventProperty("IsAuditEvent", new Serilog.Events.ScalarValue(true)),
            new Serilog.Events.LogEventProperty("AuditEntryId", new Serilog.Events.ScalarValue(Guid.NewGuid())),
            new Serilog.Events.LogEventProperty("Action", new Serilog.Events.ScalarValue(action)),
            new Serilog.Events.LogEventProperty("ResourceId", new Serilog.Events.ScalarValue(resourceId)),
            new Serilog.Events.LogEventProperty("PerformedBy", new Serilog.Events.ScalarValue("alice")),
        ]);
}
