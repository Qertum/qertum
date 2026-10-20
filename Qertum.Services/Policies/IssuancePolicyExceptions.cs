namespace Qertum.Services.Policies;

public enum PolicyEnforcementStage
{
    Create,
    Renew,
    Update,
    Approval,
    Issuance
}

/// <summary>A request failed its issuance policy. Approval-stage violations map to 422, the rest to 400.</summary>
public sealed class IssuancePolicyViolationException(PolicyDecision decision, PolicyEnforcementStage stage)
    : Exception(decision.Summarize())
{
    public PolicyDecision Decision { get; } = decision;

    public PolicyEnforcementStage Stage { get; } = stage;
}

/// <summary>A policy operation conflicts with current state (stale publish token, archived, still referenced). Maps to 409.</summary>
public sealed class IssuancePolicyConflictException(string message) : Exception(message);

/// <summary>A change would make a linked template's default validity exceed its policy maximum. Maps to 422.</summary>
public sealed class IssuancePolicyInvariantException(string message) : Exception(message);
