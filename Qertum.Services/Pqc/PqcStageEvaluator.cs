namespace Qertum.Services;

/// <summary>What the evaluator decided for one request.</summary>
public enum PqcOutcome
{
    /// <summary>Proceed silently (or with an event only).</summary>
    Allowed,
    /// <summary>Proceed, and tell the requester where the protocol has a channel.</summary>
    AllowedWithWarning,
    /// <summary>Refuse.</summary>
    Refused
}

/// <summary>Diagnostic event actions recorded for PQC stage verdicts.</summary>
public static class PqcEventActions
{
    /// <summary>Recorded at <see cref="PqcStage.Observe"/>.</summary>
    public const string Observed = "PqcObserved";
    /// <summary>Recorded when a warning is returned.</summary>
    public const string Warned = "PqcWarned";
    /// <summary>Recorded when an exception turned a refusal into a warning.</summary>
    public const string ExceptionApplied = "PqcExceptionApplied";
}

/// <summary>The evaluator's answer. <see cref="EventAction"/> null means record nothing.</summary>
public sealed record PqcVerdict(PqcOutcome Outcome, PqcStage Stage, string? Reason, string? EventAction);

/// <summary>Pure decision table for staged PQC enforcement. No I/O; unit-tested exhaustively.</summary>
public static class PqcStageEvaluator
{
    /// <summary>
    /// True for PQC, hybrid, composite, ML-KEM and signing + encryption pair keys. RSA and ECDSA are the non-compliant set.
    /// Composite cannot be downgraded to its classical half; ML-KEM is a post-quantum subject key.
    /// </summary>
    public static bool IsCompliant(CertificateKeyAlgorithm algorithm) =>
        algorithm.GetFamily() is AlgorithmFamily.Pqc or AlgorithmFamily.Hybrid
            or AlgorithmFamily.Composite or AlgorithmFamily.Kem or AlgorithmFamily.Pair;

    /// <summary>
    /// Decides one request. <paramref name="exceptionReference"/> is non-null when an active exception
    /// matched the request; it only matters when the stage would otherwise refuse.
    /// </summary>
    public static PqcVerdict Evaluate(PqcStage stage, CertificateKeyAlgorithm algorithm, bool isRenewal,
        string? exceptionReference = null)
    {
        if (IsCompliant(algorithm))
            return new PqcVerdict(PqcOutcome.Allowed, stage, null, null);

        var name = algorithm.ToCanonicalString();
        return stage switch
        {
            PqcStage.Off => new PqcVerdict(PqcOutcome.Allowed, stage, null, null),
            PqcStage.Observe => new PqcVerdict(PqcOutcome.Allowed, stage,
                $"'{name}' is a classical RSA or ECDSA algorithm (PQC stage Observe).", PqcEventActions.Observed),
            PqcStage.Warn => Warned(stage, name),
            PqcStage.Pilot when isRenewal => new PqcVerdict(PqcOutcome.AllowedWithWarning, stage,
                $"Renewing with '{name}', a classical RSA or ECDSA algorithm; new requests on this template are " +
                "refused at PQC stage Pilot.", PqcEventActions.Warned),
            PqcStage.Pilot => Refuse(stage, exceptionReference,
                $"PQC pilot stage refuses new requests; '{name}' is a classical RSA or ECDSA algorithm."),
            PqcStage.Enforce => Refuse(stage, exceptionReference,
                $"PQC enforce stage refuses classical keys; '{name}' is a classical RSA or ECDSA algorithm."),
            _ => throw new ArgumentOutOfRangeException(nameof(stage), stage, null)
        };
    }

    private static PqcVerdict Warned(PqcStage stage, string algorithm) =>
        new(PqcOutcome.AllowedWithWarning, stage,
            $"'{algorithm}' is a classical RSA or ECDSA algorithm; this template is moving to post-quantum keys (PQC stage Warn).",
            PqcEventActions.Warned);

    private static PqcVerdict Refuse(PqcStage stage, string? exceptionReference, string reason) =>
        exceptionReference is null
            ? new PqcVerdict(PqcOutcome.Refused, stage, reason, null)
            : new PqcVerdict(PqcOutcome.AllowedWithWarning, stage,
                $"{reason} Allowed by {exceptionReference}.", PqcEventActions.ExceptionApplied);
}
