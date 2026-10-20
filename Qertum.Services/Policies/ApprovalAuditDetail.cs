namespace Qertum.Services.Policies;

/// <summary>
/// A published policy version, by id (for comparison) and policy name + number (for display): two
/// policies can both have a v2, so the number alone does not say which version it was.
/// </summary>
public sealed record PolicyVersionRef(Guid Id, int Number, string PolicyName)
{
    public string Display => $"policy '{PolicyName}' v{Number}";
}

/// <summary>
/// What an approver's client says its approval preview showed before Approve was clicked: the policy
/// version the preview named (null when no policy governed it) and the verdict. Client-reported, not verified.
/// </summary>
public sealed record ApprovalPreviewReport(Guid? PolicyVersionId, bool Allowed);

/// <summary>An <see cref="ApprovalPreviewReport"/> resolved against the database at approval time; the id distinguishes an unknown version from no policy.</summary>
public sealed record ReportedPreview(bool Allowed, Guid? PolicyVersionId, int? PolicyVersionNumber, string? PolicyName, bool SameVersionAsApproval);

/// <summary>
/// The one place that words approval audit details. Pure: callers resolve versions first. Contains only
/// policy names, version numbers and the evaluator's violation messages — never key or certificate material.
/// </summary>
public static class ApprovalAuditDetail
{
    /// <summary>Approval acts for someone else, so a policy's requester roles are not re-checked there.</summary>
    public const string RequesterRolesNote = "Requester roles are checked at submission, not at approval.";

    public static string ForPreview(PolicyDecision decision, PolicyVersionRef? createdUnder)
    {
        var text = PreviewVerdict(decision, Created(decision, createdUnder));
        return decision.RequesterRolesListed ? $"{text} {RequesterRolesNote}" : text;
    }

    private static string PreviewVerdict(PolicyDecision decision, string created)
    {
        if (decision.Allowed)
        {
            return decision.PolicyName is null
                ? $"Approval preview: no issuance policy governs this request{created}."
                : $"Approval preview: policy '{decision.PolicyName}' v{decision.VersionNumber} admits this request{created}.";
        }

        var rules = decision.PolicyName is null
            ? "the issuance rules refuse"
            : $"policy '{decision.PolicyName}' v{decision.VersionNumber} refuses";
        return $"Approval preview: {rules} this request{created}: {Violations(decision)}.";
    }

    /// <summary>Appended to <c>Approved</c> when a requester approved their own CA request because independent approval is waived.</summary>
    public const string SelfApprovalWaivedNote = "Independent CA approval is waived by setting: the requester approved their own request.";

    public static string ForApproval(PolicyDecision decision, PolicyVersionRef? createdUnder, ReportedPreview? reported)
    {
        var text = $"Approved under {Governing(decision)}{Created(decision, createdUnder)}. {Preview(decision, reported)}";
        return decision.SelfApprovalWaived ? $"{text} {SelfApprovalWaivedNote}" : text;
    }

    public static string ForBlockedApproval(PolicyDecision decision, PolicyVersionRef? createdUnder, ReportedPreview? reported)
    {
        var rules = decision.PolicyName is null
            ? "the issuance rules"
            : $"policy '{decision.PolicyName}' v{decision.VersionNumber}";
        return $"Approval refused by {rules}{Created(decision, createdUnder)}: {Violations(decision)}. {Preview(decision, reported)}";
    }

    public static string ForAutoApproval(string setting, PolicyDecision decision) =>
        $"Auto-approved at creation by {setting} under {Governing(decision)}.";

    public static string ForAutoApproval(string setting, PolicyDecision decision, PolicyVersionRef? lastEvaluatedUnder) =>
        $"Auto-approved by {setting} under {Governing(decision)}{Created(decision, lastEvaluatedUnder)}.";

    public static string ForBlockedAutoApproval(string setting, PolicyDecision decision, PolicyVersionRef? lastEvaluatedUnder)
    {
        var rules = decision.PolicyName is null
            ? "the issuance rules"
            : $"policy '{decision.PolicyName}' v{decision.VersionNumber}";
        return $"Automatic approval by {setting} refused by {rules}{Created(decision, lastEvaluatedUnder)}: {Violations(decision)}.";
    }

    private static string Governing(PolicyDecision decision) =>
        decision.PolicyName is null ? "no issuance policy" : $"policy '{decision.PolicyName}' v{decision.VersionNumber}";

    private static string Created(PolicyDecision decision, PolicyVersionRef? createdUnder)
    {
        if (createdUnder is null)
            return decision.PolicyVersionId is null ? string.Empty : " (no policy version was recorded when it was last evaluated)";

        return createdUnder.Id == decision.PolicyVersionId
            ? " (same version as its last evaluation)"
            : $" (last evaluated under {createdUnder.Display}; the policy has changed since)";
    }

    private static string Preview(PolicyDecision decision, ReportedPreview? reported)
    {
        if (reported is null)
            return "The approver's client reported no preview.";

        var verdict = reported.Allowed ? "admitted" : "refused";
        if (reported.PolicyVersionId is { } unknownId && reported.PolicyVersionNumber is null)
            return $"The approver's client reported a preview with unrecognized policy version id {unknownId} that {verdict} it; its policy version could not be compared with the version used for approval.";

        var shown = reported.PolicyVersionNumber is { } number ? $"policy '{reported.PolicyName}' v{number}" : "no policy";
        if (reported.SameVersionAsApproval)
            return $"The approver's client reported a preview of {shown} that {verdict} it.";

        var current = decision.VersionNumber is { } now ? $"policy '{decision.PolicyName}' v{now}" : "no policy";
        return $"The approver's client reported a preview of {shown} that {verdict} it; the governing version changed to {current} before approval.";
    }

    private static string Violations(PolicyDecision decision) =>
        string.Join("; ", decision.Violations.Select(v => v.Message.TrimEnd('.')));
}
