using System.Diagnostics;
using Qertum.Audit;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Compact;

namespace Qertum.Tests.Engineering;

/// <summary>
/// The CA and the IdP write their audit logs through one format (Qertum.Audit). These tests write an
/// event exactly as both services do, through CompactJsonFormatter, and read it back, so a change to
/// either half that the other cannot read fails here rather than in a production file.
/// </summary>
public sealed class AuditEventFormatTests
{
    [Fact]
    public void AWrittenEventReadsBackWithEveryField()
    {
        using var activity = new Activity("audit-test").Start();
        var resourceId = Guid.NewGuid();

        var (id, line) = WriteOne(log =>
            AuditEventFormat.Write(log, "Approved", "alice", resourceId, "www.example.com", "note"));

        var parsed = AuditEventFormat.TryParse(line);

        Assert.NotNull(parsed);
        Assert.Equal(id, parsed.Id);
        Assert.Equal("Approved", parsed.Action);
        Assert.Equal("alice", parsed.PerformedBy);
        Assert.Equal(resourceId, parsed.ResourceId);
        Assert.Equal("www.example.com", parsed.ResourceName);
        Assert.Equal("note", parsed.Detail);
        Assert.Equal(activity.TraceId.ToString(), parsed.TraceId);
        Assert.Equal(DateTimeKind.Utc, parsed.OccurredAtUtc.Kind);
        Assert.True((DateTime.UtcNow - parsed.OccurredAtUtc).Duration() < TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void OptionalFieldsReadBackAsNull()
    {
        var (_, line) = WriteOne(log => AuditEventFormat.Write(log, "SettingsUpdated", "bob"));

        var parsed = AuditEventFormat.TryParse(line);

        Assert.NotNull(parsed);
        Assert.Null(parsed.ResourceId);
        Assert.Null(parsed.ResourceName);
        Assert.Null(parsed.Detail);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{\"@t\":\"2026-09-21T10:00:00Z\",\"@mt\":\"Ordinary app log\"}")]
    [InlineData("{\"@t\":\"not a date\",\"IsAuditEvent\":true,\"Action\":\"X\",\"PerformedBy\":\"y\"}")]
    public void ALineThatIsNotAnAuditEventIsSkipped(string line) =>
        Assert.Null(AuditEventFormat.TryParse(line));

    private static (Guid Id, string Line) WriteOne(Func<Serilog.ILogger, Guid> write)
    {
        var sink = new CapturingSink();
        using var log = new LoggerConfiguration().WriteTo.Sink(sink).CreateLogger();
        var id = write(log);
        return (id, Assert.Single(sink.Lines));
    }

    private sealed class CapturingSink : ILogEventSink
    {
        private readonly CompactJsonFormatter _formatter = new();
        public List<string> Lines { get; } = [];

        public void Emit(LogEvent logEvent)
        {
            using var writer = new StringWriter();
            _formatter.Format(logEvent, writer);
            Lines.Add(writer.ToString().TrimEnd());
        }
    }
    [Fact]
    public void ChainPropertyNames_AreTheOnDiskContract()
    {
        Assert.Equal("OccurredAt", AuditEventProperties.OccurredAt);
        Assert.Equal("ChainWriter", AuditEventProperties.ChainWriter);
        Assert.Equal("ChainSeq", AuditEventProperties.ChainSeq);
        Assert.Equal("ChainPrev", AuditEventProperties.ChainPrev);
        Assert.Equal("ChainHash", AuditEventProperties.ChainHash);
    }

    [Fact]
    public void TryParseChain_IgnoresUnchainedAndNonAuditLines_AndReadsAChainedOne()
    {
        Assert.Null(AuditEventFormat.TryParseChain("not json"));
        Assert.Null(AuditEventFormat.TryParseChain("""{"@t":"2026-10-14T12:00:00Z","@mt":"hello"}"""));
        Assert.Null(AuditEventFormat.TryParseChain("""{"IsAuditEvent":true,"Action":"Old","PerformedBy":"x"}"""));

        var link = AuditEventFormat.TryParseChain(
            """{"IsAuditEvent":true,"AuditEntryId":"e","OccurredAt":"t","Action":"A","PerformedBy":"p","ResourceId":null,"ChainWriter":"w","ChainSeq":7,"ChainPrev":null,"ChainHash":"h"}""");

        Assert.NotNull(link);
        Assert.Equal(("w", 7L, (string?)null, "h"), (link!.Writer, link.Seq, link.Prev, link.Hash));
        Assert.Equal("A", link.Fields.Action);
        Assert.Equal(string.Empty, link.Fields.ResourceId);
    }
}
