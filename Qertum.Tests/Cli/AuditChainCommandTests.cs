using System.Runtime.Versioning;
using System.Text.Json;
using Qertum.Audit;
using Qertum.Cli;
using Qertum.Cli.Commands;
using Serilog;
using Serilog.Formatting.Compact;

namespace Qertum.Tests.Cli;

public sealed class AuditChainCommandTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "qca-audit-" + Guid.NewGuid().ToString("N"));

    public AuditChainCommandTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private void WriteLog(int entries)
    {
        var chain = new AuditChain("api", []);
        using var log = new LoggerConfiguration()
            .WriteTo.File(new CompactJsonFormatter(), Path.Combine(_dir, "audit-.clef"), shared: true).CreateLogger();
        for (var i = 0; i < entries; i++)
            chain.Write(log, "A" + i, "alice");
    }

    private string LogFile => Directory.GetFiles(_dir, "audit-*.clef").Single();

    private static (int Code, string Out, string Err) Run(IReadOnlyList<string> paths, string? anchor = null)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        return (AuditVerifyRunner.Run(paths, anchor, output, error), output.ToString(), error.ToString());
    }

    [Fact]
    public void VerifyOnAnIntactDirectory_ExitsZero_AndNamesTheChain()
    {
        WriteLog(4);

        var (code, output, _) = Run([_dir]);

        Assert.Equal(0, code);
        Assert.Contains("api", output);
        Assert.Contains("ok", output);
    }

    [Fact]
    public void VerifyAfterAnEdit_ExitsOne_AndNamesTheLine()
    {
        WriteLog(4);
        File.WriteAllText(LogFile, File.ReadAllText(LogFile).Replace("\"Action\":\"A2\"", "\"Action\":\"X2\""));

        var (code, output, _) = Run([LogFile]);

        Assert.Equal(1, code);
        Assert.Contains("HashMismatch", output);
        Assert.Contains(":3", output);
    }

    [Fact]
    public void VerifyWithAnAnchorFromBeforeACutTail_ExitsOne()
    {
        WriteLog(5);
        var lines = File.ReadAllLines(LogFile);
        var head = AuditEventFormat.TryParseChain(lines[4])!;
        var anchor = Path.Combine(_dir, "anchor.json");
        File.WriteAllText(anchor, JsonSerializer.Serialize(new { chains = new[] { new { writer = "api", seq = 5L, hash = head.Hash } } }));
        File.WriteAllLines(LogFile, lines.Take(3));

        var (code, output, _) = Run([_dir], anchor);

        Assert.Equal(1, code);
        Assert.Contains("AnchorBeyondLog", output);
    }

    [Fact]
    public void VerifyAcceptsTheCheckpointObjectInPascalCase_AndTheBareHeadsArrayFromTheWebhook()
    {
        WriteLog(2);
        var head = AuditEventFormat.TryParseChain(File.ReadAllLines(LogFile)[1])!;

        var bare = Path.Combine(_dir, "heads.json");
        File.WriteAllText(bare, JsonSerializer.Serialize(new[] { new { writer = "api", seq = 2L, hash = head.Hash } }));
        Assert.Equal(0, Run([_dir], bare).Code);

        var pascal = Path.Combine(_dir, "checkpoint.json");
        File.WriteAllText(pascal, JsonSerializer.Serialize(new { GeneratedAtUtc = DateTime.UtcNow, Chains = new[] { new { Writer = "api", Seq = 2L, Hash = head.Hash } } }));
        Assert.Equal(0, Run([_dir], pascal).Code);
    }

    [Fact]
    public void VerifyWithNothingToRead_OrABadAnchorFile_ExitsTwo()
    {
        Assert.Equal(2, Run([Path.Combine(_dir, "missing")]).Code);
        Assert.Equal(2, Run([_dir]).Code);

        WriteLog(1);
        var bad = Path.Combine(_dir, "bad.json");
        File.WriteAllText(bad, "{ not json");
        Assert.Equal(2, Run([_dir], bad).Code);
        Assert.Equal(2, Run([_dir], Path.Combine(_dir, "no-such-anchor.json")).Code);
    }

    [Fact]
    [UnsupportedOSPlatform("windows")]
    public void VerifyOnAFileItCannotRead_ExitsTwo_NotAStackTrace()
    {
        // Root (a CI container, for one) reads any file regardless of mode, so the denial cannot be staged.
        Assert.SkipWhen(OperatingSystem.IsWindows() || Environment.IsPrivilegedProcess,
            "file permissions are not enforced for this user");

        WriteLog(2);
        File.SetUnixFileMode(LogFile, UnixFileMode.None);
        try
        {
            var (code, _, error) = Run([_dir]);

            Assert.Equal(2, code);
            Assert.Contains("could not be read", error);
        }
        finally
        {
            File.SetUnixFileMode(LogFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }

    [Fact]
    public void VerifyOnAnEmptyChainSet_SaysNothingIsChained_AndExitsZero()
    {
        File.WriteAllText(Path.Combine(_dir, "audit-20260101.clef"), "{\"IsAuditEvent\":true,\"Action\":\"Old\"}\n");

        var (code, output, _) = Run([_dir]);

        Assert.Equal(0, code);
        Assert.Contains("No chained audit entries", output);
    }

    [Fact]
    public void TheNewCommands_AreInTheTree_AndFollowTheHelpStandard()
    {
        var audit = CliRoot.Build().Subcommands.Single(c => c.Name == "audit");

        foreach (var name in new[] { "verify", "checkpoint" })
        {
            var description = audit.Subcommands.Single(c => c.Name == name).Description!;
            Assert.Contains("Needs:", description);
            Assert.Contains("Exit codes:", description);
            Assert.Contains("Example: qca audit " + name, description);
        }
    }
}
