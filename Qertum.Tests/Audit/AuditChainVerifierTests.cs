using System.Text.Json;
using Qertum.Audit;

namespace Qertum.Tests.Audit;

public sealed class AuditChainVerifierTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "audit-verify-" + Guid.NewGuid().ToString("N"));

    public AuditChainVerifierTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private static string Line(string writer, long seq, string? prev, string action = "A", string detail = "d")
    {
        var fields = new AuditChainFields($"id-{writer}-{seq}", "2026-10-14T12:00:00.0000000Z", action, "alice", "", "", detail, "");
        var hash = AuditChainHasher.Compute(prev, writer, seq, fields);
        return Json(writer, seq, prev, hash, fields);
    }

    private static string Json(string writer, long seq, string? prev, string hash, AuditChainFields f) => JsonSerializer.Serialize(new Dictionary<string, object?>
    {
        ["@t"] = "2026-10-14T12:00:00Z", ["IsAuditEvent"] = true, ["AuditEntryId"] = f.EntryId, ["OccurredAt"] = f.OccurredAt,
        ["Action"] = f.Action, ["PerformedBy"] = f.PerformedBy, ["ResourceId"] = null, ["ResourceName"] = null, ["Detail"] = f.Detail,
        ["TraceId"] = null, ["ChainWriter"] = writer, ["ChainSeq"] = seq, ["ChainPrev"] = prev, ["ChainHash"] = hash
    });

    private static string HashOf(string line) => AuditEventFormat.TryParseChain(line)!.Hash;

    /// <summary>A chain of <paramref name="count"/> lines for <paramref name="writer"/> starting at <paramref name="start"/>.</summary>
    private static List<string> Chain(string writer, int count, long start = 1, string? prev = null)
    {
        var lines = new List<string>();
        for (var i = 0; i < count; i++)
        {
            var line = Line(writer, start + i, prev);
            lines.Add(line);
            prev = HashOf(line);
        }

        return lines;
    }

    private string File(string name, IEnumerable<string> lines)
    {
        var path = Path.Combine(_dir, name);
        System.IO.File.WriteAllLines(path, lines);
        return path;
    }

    [Fact]
    public void ACleanChain_IsOk_WithItsRange()
    {
        var report = AuditChainVerifier.Verify([File("a.clef", Chain("w", 5))]);

        var chain = Assert.Single(report.Chains);
        Assert.Null(chain.Problem);
        Assert.Equal((1L, 5L, 5L), (chain.FirstSeq, chain.LastSeq, chain.Entries));
        Assert.True(report.Ok);
    }

    [Fact]
    public void AnEditedEntry_IsAHashMismatch_AtThatLine()
    {
        var lines = Chain("w", 5);
        lines[2] = lines[2].Replace("\"Detail\":\"d\"", "\"Detail\":\"changed\"");

        var problem = Assert.Single(AuditChainVerifier.Verify([File("a.clef", lines)]).Chains).Problem;

        Assert.NotNull(problem);
        Assert.Equal((AuditChainBreak.HashMismatch, 3, 3L), (problem!.Kind, problem.Line, problem.Seq));
    }

    [Fact]
    public void ADeletedEntry_IsAGap_AtTheNextLine()
    {
        var lines = Chain("w", 5);
        lines.RemoveAt(2);

        var problem = Assert.Single(AuditChainVerifier.Verify([File("a.clef", lines)]).Chains).Problem;

        Assert.Equal((AuditChainBreak.Gap, 3, 4L), (problem!.Kind, problem.Line, problem.Seq));
    }

    [Fact]
    public void ASwappedPair_IsAGap()
    {
        var lines = Chain("w", 4);
        (lines[1], lines[2]) = (lines[2], lines[1]);

        Assert.Equal(AuditChainBreak.Gap, Assert.Single(AuditChainVerifier.Verify([File("a.clef", lines)]).Chains).Problem!.Kind);
    }

    [Fact]
    public void ARepeatedEntry_IsADuplicate()
    {
        var lines = Chain("w", 3);
        lines.Insert(2, lines[1]);

        Assert.Equal(AuditChainBreak.Duplicate, Assert.Single(AuditChainVerifier.Verify([File("a.clef", lines)]).Chains).Problem!.Kind);
    }

    [Fact]
    public void AnInsertedEntryWithTheRightSequenceButWrongPrev_IsAPrevMismatch()
    {
        var lines = Chain("w", 3);
        var forged = Line("w", 3, prev: new string('f', 64));
        lines[2] = forged;

        Assert.Equal(AuditChainBreak.PrevMismatch, Assert.Single(AuditChainVerifier.Verify([File("a.clef", lines)]).Chains).Problem!.Kind);
    }

    [Fact]
    public void TwoWritersInterleavedInOneFile_BothVerify()
    {
        var a = Chain("api", 3);
        var b = Chain("queue", 3);
        var mixed = new[] { a[0], b[0], b[1], a[1], a[2], b[2] };

        var report = AuditChainVerifier.Verify([File("a.clef", mixed)]);

        Assert.Equal(2, report.Chains.Count);
        Assert.True(report.Ok);
    }

    [Fact]
    public void ALogThatStartsMidChain_BecauseOldFilesWereRetainedAway_Verifies()
    {
        var all = Chain("w", 6);

        var report = AuditChainVerifier.Verify([File("b.clef", all.Skip(3))]);

        Assert.True(report.Ok);
        Assert.Equal(4L, Assert.Single(report.Chains).FirstSeq);
    }

    [Fact]
    public void UnchainedOldLines_OtherLogLines_AndGarbage_AreIgnored()
    {
        var lines = new List<string>
        {
            """{"IsAuditEvent":true,"Action":"Old","PerformedBy":"x"}""",
            """{"@t":"2026-10-14T12:00:00Z","@mt":"hello"}""",
            "not json at all",
            ""
        };
        lines.AddRange(Chain("w", 2));

        Assert.True(AuditChainVerifier.Verify([File("a.clef", lines)]).Ok);
    }

    [Fact]
    public void ACleanChainSpanningTwoFiles_VerifiesInNameOrder()
    {
        var lines = Chain("w", 6);

        var report = AuditChainVerifier.Verify([File("b.clef", lines.Skip(3)), File("a.clef", lines.Take(3))]);

        Assert.True(report.Ok);
        Assert.Equal(6L, Assert.Single(report.Chains).Entries);
    }

    [Fact]
    public void AnEmptyInput_IsOkWithNoChains()
    {
        var report = AuditChainVerifier.Verify([]);

        Assert.True(report.Ok);
        Assert.Empty(report.Chains);
    }

    [Fact]
    public void AnAnchorThatMatches_PassesAndOneBeyondTheLog_IsATruncation()
    {
        var lines = Chain("w", 5);
        var file = File("a.clef", lines);

        Assert.True(AuditChainVerifier.Verify([file], [new AuditAnchorHead("w", 5, HashOf(lines[4]))]).Ok);

        var truncated = File("t.clef", lines.Take(3));
        var problem = Assert.Single(AuditChainVerifier.Verify([truncated], [new AuditAnchorHead("w", 5, HashOf(lines[4]))]).Chains).Problem;
        Assert.Equal(AuditChainBreak.AnchorBeyondLog, problem!.Kind);
    }

    [Fact]
    public void AnAnchorWithAWrongHash_OrForAnUnknownWriter_IsReported()
    {
        var lines = Chain("w", 3);
        var file = File("a.clef", lines);

        var mismatch = AuditChainVerifier.Verify([file], [new AuditAnchorHead("w", 2, new string('0', 64))]);
        Assert.Equal(AuditChainBreak.AnchorMismatch, Assert.Single(mismatch.Chains).Problem!.Kind);

        var missing = AuditChainVerifier.Verify([file], [new AuditAnchorHead("ghost", 1, new string('0', 64))]);
        Assert.Contains(missing.Chains, c => c.Writer == "ghost" && c.Problem?.Kind == AuditChainBreak.AnchorMissing);
        Assert.False(missing.Ok);
    }

    [Fact]
    public void AnAnchorOlderThanTheLogStart_IsMissing_NotMatched()
    {
        var all = Chain("w", 6);
        var file = File("b.clef", all.Skip(3));

        var report = AuditChainVerifier.Verify([file], [new AuditAnchorHead("w", 2, HashOf(all[1]))]);

        Assert.Equal(AuditChainBreak.AnchorMissing, Assert.Single(report.Chains).Problem!.Kind);
    }

    [Fact]
    public void AnAnchorListingTheSameHeadTwice_IsFine_AndTwoDifferentHashesForOneSeqIsAMismatch()
    {
        var lines = Chain("w", 3);
        var file = File("a.clef", lines);
        var good = new AuditAnchorHead("w", 3, HashOf(lines[2]));

        Assert.True(AuditChainVerifier.Verify([file], [good, good]).Ok);

        var conflicting = AuditChainVerifier.Verify([file], [good, good with { Hash = new string('0', 64) }]);
        Assert.Equal(AuditChainBreak.AnchorMismatch, Assert.Single(conflicting.Chains).Problem!.Kind);
    }
}
