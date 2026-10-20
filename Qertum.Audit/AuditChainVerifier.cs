namespace Qertum.Audit;

/// <summary>What is wrong with a chain.</summary>
public enum AuditChainBreak
{
    /// <summary>The recomputed hash differs from the stored one: the entry was edited.</summary>
    HashMismatch,

    /// <summary>The sequence skipped a number: an entry was deleted, swapped or lost.</summary>
    Gap,

    /// <summary>The entry's previous-hash does not match the previous entry.</summary>
    PrevMismatch,

    /// <summary>The same sequence number appears twice.</summary>
    Duplicate,

    /// <summary>The anchor names a writer (or a sequence older than the log start) the log does not contain.</summary>
    AnchorMissing,

    /// <summary>The anchored sequence exists but its hash differs.</summary>
    AnchorMismatch,

    /// <summary>The log ends before the anchored sequence: the tail was cut or the log was restored from an older copy.</summary>
    AnchorBeyondLog
}

/// <summary>The first problem found in one chain.</summary>
/// <param name="Kind">What is wrong.</param>
/// <param name="File">The file path (empty for anchor problems).</param>
/// <param name="Line">1-based line number in the file (0 for anchor problems).</param>
/// <param name="Seq">The chain sequence at the problem, when known.</param>
public sealed record AuditChainProblem(AuditChainBreak Kind, string File, int Line, long? Seq);

/// <summary>The verification of one writer's chain.</summary>
/// <param name="Writer">The chain name.</param>
/// <param name="FirstSeq">First sequence found (the log may start mid-chain after retention).</param>
/// <param name="LastSeq">Last sequence verified.</param>
/// <param name="Entries">How many entries were verified.</param>
/// <param name="Problem">The first problem, or null when the chain is intact.</param>
public sealed record AuditChainResult(string Writer, long FirstSeq, long LastSeq, long Entries, AuditChainProblem? Problem);

/// <summary>All chains found in a set of files.</summary>
/// <param name="Chains">One result per writer, ordered by name.</param>
public sealed record AuditChainReport(IReadOnlyList<AuditChainResult> Chains)
{
    /// <summary>True when no chain has a problem.</summary>
    public bool Ok => Chains.All(c => c.Problem is null);
}

/// <summary>The head of one writer's chain as recorded in a checkpoint held off-host.</summary>
/// <param name="Writer">The chain name.</param>
/// <param name="Seq">The sequence number the checkpoint recorded.</param>
/// <param name="Hash">The hash the checkpoint recorded for that sequence.</param>
public sealed record AuditAnchorHead(string Writer, long Seq, string Hash);

/// <summary>
/// Checks audit chains in CLEF files without a database or a clock. Lines without chain properties (written before
/// the chain existed) and lines that are not audit events are ignored; a writer's first chained line starts its
/// chain, so a log whose oldest files were retained away still verifies.
/// </summary>
public static class AuditChainVerifier
{
    /// <summary>Verifies every chain in <paramref name="files"/>, read in file-name order, and checks <paramref name="anchor"/> when given.</summary>
    /// <param name="files">CLEF file paths; ordered by name so date-stamped rolling files read oldest first.</param>
    /// <param name="anchor">Heads from a checkpoint kept off-host, or null.</param>
    public static AuditChainReport Verify(IEnumerable<string> files, IReadOnlyList<AuditAnchorHead>? anchor = null)
    {
        var states = new Dictionary<string, State>(StringComparer.Ordinal);
        // The same head listed twice is normal (a quiet system repeats it every checkpoint); two hashes for one
        // sequence number can never both be right, so they are kept apart and reported as a mismatch.
        var wanted = (anchor ?? []).GroupBy(a => a.Writer, StringComparer.Ordinal)
            .ToDictionary(g => g.Key,
                g => g.GroupBy(a => a.Seq).ToDictionary(x => x.Key, x => x.Select(a => a.Hash).Distinct(StringComparer.Ordinal).ToList()),
                StringComparer.Ordinal);

        foreach (var file in files.OrderBy(f => f, StringComparer.Ordinal))
        {
            var lineNumber = 0;
            foreach (var line in ReadLines(file))
            {
                lineNumber++;
                if (AuditEventFormat.TryParseChain(line) is not { } link)
                    continue;

                if (!states.TryGetValue(link.Writer, out var state))
                    states[link.Writer] = state = new State();
                if (state.Problem is not null)
                    continue;

                Check(state, link, file, lineNumber);
                if (state.Problem is null && wanted.TryGetValue(link.Writer, out var seqs) && seqs.ContainsKey(link.Seq))
                    state.Seen[link.Seq] = link.Hash;
            }
        }

        var results = new List<AuditChainResult>();
        foreach (var (writer, state) in states.OrderBy(p => p.Key, StringComparer.Ordinal))
            results.Add(new AuditChainResult(writer, state.First, state.Last, state.Entries,
                state.Problem ?? AnchorProblem(writer, state, wanted)));

        foreach (var writer in wanted.Keys.Where(w => !states.ContainsKey(w)).OrderBy(w => w, StringComparer.Ordinal))
            results.Add(new AuditChainResult(writer, 0, 0, 0, new AuditChainProblem(AuditChainBreak.AnchorMissing, string.Empty, 0, null)));

        return new AuditChainReport(results);
    }

    private static void Check(State state, ChainLink link, string file, int lineNumber)
    {
        if (state.Entries > 0)
        {
            if (link.Seq == state.Last)
                state.Problem = new AuditChainProblem(AuditChainBreak.Duplicate, file, lineNumber, link.Seq);
            else if (link.Seq != state.Last + 1)
                state.Problem = new AuditChainProblem(AuditChainBreak.Gap, file, lineNumber, link.Seq);
            else if (!string.Equals(link.Prev, state.LastHash, StringComparison.Ordinal))
                state.Problem = new AuditChainProblem(AuditChainBreak.PrevMismatch, file, lineNumber, link.Seq);
            if (state.Problem is not null)
                return;
        }

        var expected = AuditChainHasher.Compute(link.Prev, link.Writer, link.Seq, link.Fields);
        if (!string.Equals(expected, link.Hash, StringComparison.Ordinal))
        {
            state.Problem = new AuditChainProblem(AuditChainBreak.HashMismatch, file, lineNumber, link.Seq);
            return;
        }

        if (state.Entries == 0)
            state.First = link.Seq;
        state.Last = link.Seq;
        state.LastHash = link.Hash;
        state.Entries++;
    }

    private static AuditChainProblem? AnchorProblem(string writer, State state, Dictionary<string, Dictionary<long, List<string>>> wanted)
    {
        if (!wanted.TryGetValue(writer, out var seqs))
            return null;

        foreach (var (seq, hashes) in seqs.OrderBy(p => p.Key))
        {
            if (seq > state.Last)
                return new AuditChainProblem(AuditChainBreak.AnchorBeyondLog, string.Empty, 0, seq);
            if (seq < state.First)
                return new AuditChainProblem(AuditChainBreak.AnchorMissing, string.Empty, 0, seq);
            if (hashes.Count != 1 || !state.Seen.TryGetValue(seq, out var found) || !string.Equals(found, hashes[0], StringComparison.Ordinal))
                return new AuditChainProblem(AuditChainBreak.AnchorMismatch, string.Empty, 0, seq);
        }

        return null;
    }

    private static IEnumerable<string> ReadLines(string file)
    {
        // FileShare.ReadWrite: the live file may still be open for appending.
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        while (reader.ReadLine() is { } line)
            yield return line;
    }

    private sealed class State
    {
        public long First;
        public long Last;
        public long Entries;
        public string? LastHash;
        public AuditChainProblem? Problem;
        public Dictionary<long, string> Seen { get; } = [];
    }
}
