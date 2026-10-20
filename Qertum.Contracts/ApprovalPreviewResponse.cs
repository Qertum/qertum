namespace Qertum.Services;

/// <summary>
/// What approving a Pending request would meet right now: the current published policy's verdict,
/// and the version the request was last evaluated under. Advisory; approval re-evaluates.
/// </summary>
public sealed class ApprovalPreviewResponse
{
    /// <summary>True when the current published policy admits the request.</summary>
    public bool Allowed { get; init; }

    /// <summary>Every rule the request breaks under the current policy; empty when admitted.</summary>
    public IReadOnlyList<IssuancePolicyViolation> Violations { get; init; } = [];

    /// <summary>Name of the policy that governs the request now, or null when none does.</summary>
    public string? PolicyName { get; init; }

    /// <summary>The published version evaluated now; send it back as <c>PreviewedPolicyVersionId</c> when approving.</summary>
    public Guid? PolicyVersionId { get; init; }

    /// <summary>Number of <see cref="PolicyVersionId"/>.</summary>
    public int? PolicyVersionNumber { get; init; }

    /// <summary>The version the request was last evaluated under (at creation or last update), or null.</summary>
    public Guid? EvaluatedPolicyVersionId { get; init; }

    /// <summary>Number of <see cref="EvaluatedPolicyVersionId"/>.</summary>
    public int? EvaluatedPolicyVersionNumber { get; init; }

    /// <summary>
    /// Name of the policy <see cref="EvaluatedPolicyVersionId"/> belongs to. A template moved to
    /// another policy can show the same number under a different name.
    /// </summary>
    public string? EvaluatedPolicyName { get; init; }

    /// <summary>UTC time of that earlier evaluation, or null.</summary>
    public DateTime? EvaluatedAtUtc { get; init; }

    /// <summary>True when the governing version differs from the one the request was last evaluated under.</summary>
    public bool PolicyChangedSinceEvaluation { get; init; }

    /// <summary>
    /// True when the governing version lists requester roles: they were checked when the request
    /// was submitted, not now, because approval acts for someone else.
    /// </summary>
    public bool RequesterRolesCheckedAtSubmission { get; init; }
}
