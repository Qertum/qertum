namespace Qertum.Services.Recovery;

/// <summary>How one restore usability check ended.</summary>
public enum RestoreCheckOutcome
{
    /// <summary>The check ran and the restored data behaved correctly.</summary>
    Pass,

    /// <summary>The check ran and the restored data is broken.</summary>
    Fail,

    /// <summary>There was nothing to test (for example no encrypted secret is stored).</summary>
    NotExercised,

    /// <summary>The check cannot say anything about this backup with this image or environment.</summary>
    NotTestable
}

/// <summary>The outcome of one named check and a short, content-free explanation.</summary>
/// <param name="Name">One of <c>database</c>, <c>key-ring</c>, <c>signing</c>, <c>revocation</c>.</param>
/// <param name="Outcome">How the check ended.</param>
/// <param name="Detail">Counts and fixed phrases only, never file or certificate content.</param>
public sealed record RestoreCheckResult(string Name, RestoreCheckOutcome Outcome, string Detail)
{
    /// <summary>The line the console tool prints: <c>check &lt;name&gt; &lt;outcome&gt; &lt;detail&gt;</c>.</summary>
    public string Line => $"check {Name} {Outcome switch
    {
        RestoreCheckOutcome.Pass => "pass",
        RestoreCheckOutcome.Fail => "fail",
        RestoreCheckOutcome.NotExercised => "not-exercised",
        _ => "not-testable"
    }} {Detail}";
}

/// <summary>All check results of one run and the process exit code they imply.</summary>
/// <param name="Results">The results in the order the checks ran.</param>
public sealed record RestoreUsabilityReport(IReadOnlyList<RestoreCheckResult> Results)
{
    /// <summary><c>1</c> when any check failed, else <c>2</c> when any was not testable, else <c>0</c>.</summary>
    public int ExitCode =>
        Results.Any(r => r.Outcome == RestoreCheckOutcome.Fail) ? 1
        : Results.Any(r => r.Outcome == RestoreCheckOutcome.NotTestable) ? 2
        : 0;

    /// <summary>The printable lines, one per result.</summary>
    public IEnumerable<string> Lines => Results.Select(r => r.Line);
}
