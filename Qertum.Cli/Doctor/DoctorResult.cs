namespace Qertum.Cli.Doctor;

/// <summary>How one check came out. <see cref="Skipped"/> means it did not run and is never a pass.</summary>
internal enum DoctorStatus { Pass, Warn, Fail, Skipped }

/// <summary>
/// One check's outcome: what it verified, what it did not verify, any problems found, and the next step.
/// A skipped result always carries its <see cref="Reason"/>.
/// </summary>
internal sealed record DoctorResult(
    string Id,
    DoctorStatus Status,
    string Summary,
    IReadOnlyList<string> Verified,
    IReadOnlyList<string> NotVerified,
    IReadOnlyList<string> Findings,
    string? Hint,
    string? Reason)
{
    public static DoctorResult Of(string id, DoctorStatus status, string summary,
        IEnumerable<string>? verified = null, IEnumerable<string>? notVerified = null,
        IEnumerable<string>? findings = null, string? hint = null) =>
        new(id, status, summary, [.. verified ?? []], [.. notVerified ?? []], [.. findings ?? []], hint, null);

    public static DoctorResult Skip(string id, string reason) =>
        new(id, DoctorStatus.Skipped, reason, [], [], [], null, reason);
}

/// <summary>Every check's result and the exit code they add up to.</summary>
internal sealed record DoctorReport(IReadOnlyList<DoctorResult> Results)
{
    public int Passed => Results.Count(r => r.Status == DoctorStatus.Pass);

    public int Warnings => Results.Count(r => r.Status == DoctorStatus.Warn);

    public int Failed => Results.Count(r => r.Status == DoctorStatus.Fail);

    public int Skipped => Results.Count(r => r.Status == DoctorStatus.Skipped);

    /// <summary>1 when any check failed, 2 when only warnings, else 0. Skips never change it.</summary>
    public int ExitCode => Failed > 0 ? 1 : Warnings > 0 ? 2 : 0;
}

/// <summary>One diagnostic. Reads what earlier checks left in <see cref="DoctorContext.Shared"/>.</summary>
internal interface IDoctorCheck
{
    string Id { get; }

    Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct);
}
