using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Policies;

/// <summary>Predicts what the create path would do with a request, without writing anything.</summary>
public interface ICertificateRequestPreviewService
{
    /// <summary>
    /// Runs every check <see cref="CertificateRequestService.CreateAsync"/> makes before it inserts
    /// a row, collecting all failures rather than stopping at the first. Advisory only: enforcement
    /// happens again for real at create, approval and issuance.
    /// </summary>
    Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, CancellationToken cancellationToken = default);

    /// <summary>As the other overload, checking the requester-role rule for <paramref name="requester"/> as create would.</summary>
    Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, RequesterRoles? requester, CancellationToken cancellationToken = default);

    /// <summary>As the other overloads, also checking the CA permission rule for <paramref name="caller"/>; null skips it.</summary>
    Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates a Pending request exactly as approval would, against the current published policy.
    /// Writes one <c>ApprovalPreviewed</c> audit entry and nothing else. Throws
    /// <see cref="ArgumentException"/> for a request that is not Pending.
    /// </summary>
    Task<ApprovalPreviewResponse> PreviewApprovalAsync(
        CertificateRequest pending, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>As the other overload, also judging the CA permission and independent-approver rules for <paramref name="caller"/>; null skips them.</summary>
    Task<ApprovalPreviewResponse> PreviewApprovalAsync(
        CertificateRequest pending, string performedBy, CallerContext? caller, CancellationToken cancellationToken);
}

internal sealed class CertificateRequestPreviewService(
    CertificateRequestDbContext db,
    IIssuancePolicyService policyService,
    IAuditLogService auditLog,
    IPqcStageService pqcStage) : ICertificateRequestPreviewService
{
    public Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, CancellationToken cancellationToken = default)
        => PreviewCreateAsync(candidate, requester: null, caller: null, cancellationToken);

    public Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, RequesterRoles? requester, CancellationToken cancellationToken = default)
        => PreviewCreateAsync(candidate, requester, caller: null, cancellationToken);

    public async Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CertificateRequest candidate, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        // Read-only on purpose: ICertificateRequestService.GetSettingsAsync inserts the singleton
        // row when it is missing, and a preview must not write anything.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken)
                       ?? new CaSettings { Id = 1 };
        var effectiveAlgorithm = candidate.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;

        var template = await db.CertificateTemplates
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.TypeKey == candidate.Type, cancellationToken);

        var violations = new List<IssuancePolicyViolation>();

        // The evaluator reports a missing template itself; this lookup only decides what the
        // response can say about validity, since without a template there is no default to report.
        var decision = await policyService.EvaluateAsync(candidate, settings, requester, caller, cancellationToken);
        violations.AddRange(decision.Violations);

        // Evaluated, never recorded: a preview writes nothing.
        var pqcVerdict = await pqcStage.EvaluateAsync(
            PqcContext.FromRequest(candidate, effectiveAlgorithm, candidate.RenewedFromId is not null), cancellationToken);
        if (pqcVerdict.Outcome == PqcOutcome.Refused)
        {
            violations.Add(new IssuancePolicyViolation(PolicyRules.PqcOnly,
                effectiveAlgorithm.ToCanonicalString(), pqcVerdict.Reason!));
        }
        var warnings = pqcVerdict.Outcome == PqcOutcome.AllowedWithWarning && pqcVerdict.Reason is not null
            ? new[] { pqcVerdict.Reason }
            : [];

        if (ActiveCommonNameRule.Applies(candidate) &&
            await ActiveCommonNameRule.IsTakenAsync(db, candidate.CommonName, cancellationToken))
        {
            violations.Add(new IssuancePolicyViolation(PolicyRules.DuplicateCommonName, candidate.CommonName,
                $"An active request already exists for '{candidate.CommonName}'."));
        }

        return new CertificateRequestPreviewResponse
        {
            Allowed = violations.Count == 0,
            Violations = violations,
            PolicyName = decision.PolicyName,
            PolicyVersionNumber = decision.VersionNumber,
            PolicyVersionId = decision.PolicyVersionId,
            TemplateTypeKey = candidate.Type ?? string.Empty,
            TemplateExists = template is not null,
            EffectiveValidityDays = template is null
                ? 0
                : ValidityDefaults.EffectiveValidityDays(candidate, template, settings),
            EffectiveKeyAlgorithm = effectiveAlgorithm.ToCanonicalString(),
            Warnings = warnings
        };
    }

    public Task<ApprovalPreviewResponse> PreviewApprovalAsync(
        CertificateRequest pending, string performedBy, CancellationToken cancellationToken = default)
        => PreviewApprovalAsync(pending, performedBy, caller: null, cancellationToken);

    public async Task<ApprovalPreviewResponse> PreviewApprovalAsync(
        CertificateRequest pending, string performedBy, CallerContext? caller, CancellationToken cancellationToken)
    {
        if (pending.Status != CertificateRequestStatus.Pending)
            throw new ArgumentException("Only a Pending request can be previewed for approval.", nameof(pending));

        // Same read-only settings read as the create preview: GetSettingsAsync would insert the row.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken)
                       ?? new CaSettings { Id = 1 };
        var decision = await policyService.EvaluateApprovalAsync(pending, settings, caller, cancellationToken);

        // Approval refuses a key the current PQC stage refuses, so the preview must say so too.
        var pqcVerdict = await pqcStage.EvaluateAsync(
            PqcContext.FromRequest(pending, pending.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa,
                pending.RenewedFromId is not null), cancellationToken);
        if (pqcVerdict.Outcome == PqcOutcome.Refused)
            decision = decision with
            {
                Allowed = false,
                Violations = [.. decision.Violations, new IssuancePolicyViolation(PolicyRules.PqcOnly,
                    (pending.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa).ToCanonicalString(), pqcVerdict.Reason!)]
            };
        var evaluatedUnder = await PolicyVersionLookup.FindAsync(db, pending.PolicyVersionId, cancellationToken);

        // Reading the verdict is the audited act: an auditor can see who looked, and what they saw.
        await auditLog.LogAsync("ApprovalPreviewed", performedBy, (Guid)pending.Id, pending.CommonName,
            ApprovalAuditDetail.ForPreview(decision, evaluatedUnder), cancellationToken);

        return new ApprovalPreviewResponse
        {
            Allowed = decision.Allowed,
            Violations = decision.Violations,
            PolicyName = decision.PolicyName,
            PolicyVersionId = decision.PolicyVersionId,
            PolicyVersionNumber = decision.VersionNumber,
            EvaluatedPolicyVersionId = pending.PolicyVersionId,
            EvaluatedPolicyVersionNumber = evaluatedUnder?.Number,
            EvaluatedPolicyName = evaluatedUnder?.PolicyName,
            EvaluatedAtUtc = pending.PolicyEvaluatedAtUtc,
            PolicyChangedSinceEvaluation = pending.PolicyVersionId != decision.PolicyVersionId,
            RequesterRolesCheckedAtSubmission = decision.RequesterRolesListed
        };
    }
}
