using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Audit;
using Qertum.Services;
using Serilog;
using Serilog.Formatting.Compact;

namespace Qertum.Tests.Audit;

public sealed class AuditChainTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "audit-chain-" + Guid.NewGuid().ToString("N"));
    private string Pattern => Path.Combine(_dir, "audit-.clef");

    public AuditChainTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private Serilog.Core.Logger Logger() => new LoggerConfiguration()
        .WriteTo.File(new CompactJsonFormatter(), Pattern, rollingInterval: RollingInterval.Day, shared: true)
        .CreateLogger();

    private string[] Files => Directory.GetFiles(_dir, "audit-*.clef");

    [Fact]
    public void WrittenEntries_FormAChainThatVerifiesFromTheRealFile()
    {
        var chain = new AuditChain("w1", AuditLogFiles.NewestFirst(Pattern));
        using (var log = Logger())
        {
            chain.Write(log, "A", "alice", Guid.NewGuid(), "res", "detail with \"quotes\" and ünïcode");
            chain.Write(log, "B", "bob");
            chain.Write(log, "C", "carol", null, null, null);
        }

        var report = AuditChainVerifier.Verify(Files);

        Assert.True(report.Ok);
        Assert.Equal(3L, Assert.Single(report.Chains).Entries);
    }

    [Fact]
    public void ARestart_ContinuesTheChain_InsteadOfStartingOverAtOne()
    {
        using (var log = Logger())
        {
            var first = new AuditChain("w1", AuditLogFiles.NewestFirst(Pattern));
            first.Write(log, "A", "alice");
            first.Write(log, "B", "alice");
        }

        using (var log = Logger())
        {
            var restarted = new AuditChain("w1", AuditLogFiles.NewestFirst(Pattern));
            restarted.Write(log, "C", "alice");
        }

        var chain = Assert.Single(AuditChainVerifier.Verify(Files).Chains);
        Assert.Null(chain.Problem);
        Assert.Equal((1L, 3L), (chain.FirstSeq, chain.LastSeq));
    }

    [Fact]
    public void AQuietWritersHead_IsRecovered_EvenWhenManyNewerFilesBelongToOtherWriters()
    {
        // The queue consumer wrote once, then the API wrote on four later days. A restart must continue the queue chain.
        string Day(string stamp) => Path.Combine(_dir, $"audit-{stamp}.clef");
        var queue = new AuditChain("queue", []);
        var api = new AuditChain("api", []);
        using (var log = new LoggerConfiguration().WriteTo.File(new CompactJsonFormatter(), Day("20260101")).CreateLogger())
        {
            queue.Write(log, "Q1", "svc");
            queue.Write(log, "Q2", "svc");
        }

        foreach (var stamp in new[] { "20260102", "20260103", "20260104", "20260105" })
            using (var log = new LoggerConfiguration().WriteTo.File(new CompactJsonFormatter(), Day(stamp)).CreateLogger())
                api.Write(log, "A", "svc");

        var restarted = new AuditChain("queue", AuditLogFiles.NewestFirst(Pattern));
        using (var log = new LoggerConfiguration().WriteTo.File(new CompactJsonFormatter(), Day("20260106")).CreateLogger())
            restarted.Write(log, "Q3", "svc");

        var report = AuditChainVerifier.Verify(Files);
        Assert.True(report.Ok);
        Assert.Equal(3L, report.Chains.Single(c => c.Writer == "queue").LastSeq);
    }

    [Fact]
    public async Task TwoWritersAppendingToOneFileConcurrently_BothChainsStayIntact()
    {
        var a = new AuditChain("api", AuditLogFiles.NewestFirst(Pattern));
        var b = new AuditChain("queue", AuditLogFiles.NewestFirst(Pattern));
        using (var logA = Logger())
        using (var logB = Logger())
        {
            await Task.WhenAll(
                Task.Run(() => { for (var i = 0; i < 50; i++) a.Write(logA, "A", "x"); }, TestContext.Current.CancellationToken),
                Task.Run(() => { for (var i = 0; i < 50; i++) b.Write(logB, "B", "y"); }, TestContext.Current.CancellationToken));
        }

        var report = AuditChainVerifier.Verify(Files);

        Assert.True(report.Ok);
        Assert.Equal([50L, 50L], report.Chains.Select(c => c.Entries));
    }

    [Fact]
    public async Task OneWriterFromManyThreads_KeepsItsFileOrderInSequence()
    {
        var chain = new AuditChain("w", AuditLogFiles.NewestFirst(Pattern));
        using (var log = Logger())
        {
            await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
                Task.Run(() => { for (var i = 0; i < 25; i++) chain.Write(log, "A", "x"); }, TestContext.Current.CancellationToken)));
        }

        Assert.True(AuditChainVerifier.Verify(Files).Ok);
    }

    [Fact]
    public void LinesWrittenBeforeTheChainExisted_AreIgnored_AndTheChainStartsAfterThem()
    {
        File.WriteAllText(Path.Combine(_dir, "audit-20260101.clef"), """{"IsAuditEvent":true,"Action":"Old","PerformedBy":"x"}""" + "\n");
        var chain = new AuditChain("w", AuditLogFiles.NewestFirst(Pattern));
        using (var log = Logger())
            chain.Write(log, "New", "alice");

        Assert.True(AuditChainVerifier.Verify(Files).Ok);
    }

    [Fact]
    public async Task TheServiceWritesAChainedFile_WhenBuiltThroughTheHostRegistration()
    {
        var settings = new Dictionary<string, string?> { ["AuditLog:File:Path"] = Pattern };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        services.AddDistributedMemoryCache();
        services.AddCustomCaServices($"Data Source={Path.Combine(_dir, "certificate-requests.db")}");
        await using (var provider = services.BuildServiceProvider())
        {
            await using (var scope = provider.CreateAsyncScope())
                await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().Database.MigrateAsync(TestContext.Current.CancellationToken);

            var audit = provider.GetRequiredService<IAuditLogService>();
            await audit.LogAsync("One", "alice", cancellationToken: TestContext.Current.CancellationToken);
            await audit.LogAsync("Two", "alice", Guid.NewGuid(), "res", "detail", TestContext.Current.CancellationToken);
            ((IDisposable)audit).Dispose();
        }

        var chain = Assert.Single(AuditChainVerifier.Verify(Files).Chains);
        Assert.Null(chain.Problem);
        Assert.Equal(2L, chain.Entries);
        Assert.Equal(AuditChain.DefaultWriter(), chain.Writer);
    }
}
