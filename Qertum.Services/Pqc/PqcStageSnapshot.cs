namespace Qertum.Services;

/// <summary>A verdict plus the exception that produced it, when one did.</summary>
public sealed record PqcEvaluation(PqcVerdict Verdict, PqcExceptionId? ExceptionId);

/// <summary>
/// Everything one stage decision reads — the CA default, template overrides and the exceptions active
/// now — loaded once so many requests can be judged without a query each. <see cref="StageOverride"/>
/// stands in for every template's stage (the migration report's "proposed stage"); it changes nothing
/// else, so a proposal is judged by exactly the rules and exceptions issuance uses.
/// </summary>
public sealed class PqcStageSnapshot
{
    private readonly IReadOnlyDictionary<string, PqcStage?> _templateOverrides;
    private readonly IReadOnlyList<PqcException> _exceptions;
    private readonly DateTime _nowUtc;

    internal PqcStageSnapshot(PqcStage defaultStage, IReadOnlyDictionary<string, PqcStage?> templateOverrides,
        IReadOnlyList<PqcException> activeExceptions, PqcStage? stageOverride, DateTime nowUtc)
    {
        DefaultStage = defaultStage;
        _templateOverrides = templateOverrides;
        _exceptions = activeExceptions;
        StageOverride = stageOverride;
        _nowUtc = nowUtc;
    }

    /// <summary>The CA-wide default; <see cref="PqcStage.Enforce"/> when no settings row exists.</summary>
    public PqcStage DefaultStage { get; }

    /// <summary>The proposed stage that replaces every template's stage, or null when judging today's rules.</summary>
    public PqcStage? StageOverride { get; }

    /// <summary>The stage in force today for a template (its override, else the default); CA keys use the default. Ignores <see cref="StageOverride"/>.</summary>
    public PqcStage CurrentStageFor(string? templateTypeKey, bool isCaKey) =>
        !isCaKey && templateTypeKey is { } key && _templateOverrides.TryGetValue(key, out var stage) && stage is { } own
            ? own
            : DefaultStage;

    /// <summary>The stage this snapshot judges under: <see cref="StageOverride"/> when set, else <see cref="CurrentStageFor"/>.</summary>
    public PqcStage EffectiveStageFor(string? templateTypeKey, bool isCaKey) =>
        StageOverride ?? CurrentStageFor(templateTypeKey, isCaKey);

    /// <summary>Decides one request. Pure over the loaded data: no I/O, writes nothing.</summary>
    public PqcEvaluation Evaluate(PqcContext context)
    {
        var stage = EffectiveStageFor(context.TemplateTypeKey, context.IsCaKey);

        string? reference = null;
        PqcExceptionId? exceptionId = null;
        if (!context.IsCaKey && stage is PqcStage.Pilot or PqcStage.Enforce && !PqcStageEvaluator.IsCompliant(context.Algorithm))
        {
            var match = _exceptions.FirstOrDefault(e => PqcExceptionMatcher.Matches(
                e, context.TemplateTypeKey, context.Algorithm, context.DnsNames, context.HasNonDnsNames, _nowUtc));
            if (match is not null)
            {
                reference = $"PQC exception {match.Id}";
                exceptionId = match.Id;
            }
        }

        var verdict = PqcStageEvaluator.Evaluate(stage, context.Algorithm, context.IsRenewal, reference);
        // The id is reported only when the exception actually decided the outcome.
        return new PqcEvaluation(verdict, verdict.EventAction == PqcEventActions.ExceptionApplied ? exceptionId : null);
    }
}
