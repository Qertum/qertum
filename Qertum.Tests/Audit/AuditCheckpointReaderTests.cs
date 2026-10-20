using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Audit;
using Qertum.Services;
using Serilog;
using Serilog.Formatting.Compact;

namespace Qertum.Tests.Audit;

public sealed class AuditCheckpointReaderTests : IDisposable
{
    private readonly string _data = Path.Combine(Path.GetTempPath(), "audit-cp-" + Guid.NewGuid().ToString("N"));
    private string Audit => Path.Combine(_data, "audit-logs", "audit-.clef");
    private string IdentityDir => Path.Combine(_data, "identity", "audit-logs");

    public AuditCheckpointReaderTests() => Directory.CreateDirectory(Path.Combine(_data, "audit-logs"));

    public void Dispose()
    {
        try { Directory.Delete(_data, recursive: true); } catch { /* best effort */ }
    }

    private static Serilog.Core.Logger Logger(string pattern) => new LoggerConfiguration()
        .WriteTo.File(new CompactJsonFormatter(), pattern, rollingInterval: RollingInterval.Day, shared: true).CreateLogger();

    private AuditCheckpointReader Reader(string identityDirectory = "") => new(
        Options.Create(new AuditLogOptions
        {
            File = { Path = Audit },
            Checkpoint = { IdentityDirectory = identityDirectory }
        }),
        new SecretStorageOptions { DataDirectory = _data },
        new FakeTimeProvider(new DateTimeOffset(2026, 10, 14, 12, 0, 0, TimeSpan.Zero)));

    [Fact]
    public void NoFiles_IsAnEmptyCheckpoint_NotAnError()
    {
        var checkpoint = Reader().Read();

        Assert.Empty(checkpoint.Chains);
        Assert.Equal(new DateTime(2026, 10, 14, 12, 0, 0, DateTimeKind.Utc), checkpoint.GeneratedAtUtc);
    }

    [Fact]
    public void TheHeadOfEveryWriter_IsTheHighestSequenceItWrote()
    {
        var api = new AuditChain("api", []);
        var queue = new AuditChain("queue", []);
        using (var log = Logger(Audit))
        {
            api.Write(log, "A", "x");
            queue.Write(log, "B", "x");
            api.Write(log, "C", "x");
        }

        var chains = Reader().Read().Chains;

        Assert.Equal(["api", "queue"], chains.Select(c => c.Writer));
        Assert.Equal([2L, 1L], chains.Select(c => c.Seq));
        Assert.All(chains, c => Assert.Equal(64, c.Hash.Length));
    }

    [Fact]
    public void TheIdentityDirectory_IsIncluded_WhenItExistsBesideTheData_OrWhenConfigured()
    {
        Directory.CreateDirectory(IdentityDir);
        var identity = new AuditChain("identity", []);
        using (var log = Logger(Path.Combine(IdentityDir, "identity-audit-.clef")))
            identity.Write(log, "UserCreated", "admin");

        Assert.Contains(Reader().Read().Chains, c => c.Writer == "identity");

        var elsewhere = Path.Combine(_data, "elsewhere");
        Directory.CreateDirectory(elsewhere);
        File.Move(Directory.GetFiles(IdentityDir).Single(), Path.Combine(elsewhere, "identity-audit-20260101.clef"));
        Directory.Delete(IdentityDir);

        Assert.Contains(Reader(elsewhere).Read().Chains, c => c.Writer == "identity");
    }

    [Fact]
    public void GarbageAndUnchainedLines_AreSkipped()
    {
        File.WriteAllText(Path.Combine(_data, "audit-logs", "audit-20260101.clef"),
            "not json\n{\"IsAuditEvent\":true,\"Action\":\"Old\"}\n\n");

        Assert.Empty(Reader().Read().Chains);
    }
}
