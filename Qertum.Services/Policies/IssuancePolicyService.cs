using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Policies;

public interface IIssuancePolicyService
{
    /// <summary>Loads the request's template and that template's published policy version, then evaluates.</summary>
    Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, CancellationToken cancellationToken = default);

    /// <summary>As <see cref="EvaluateAsync(CertificateRequest, CaSettings, CancellationToken)"/>, checking the requester-role rule for <paramref name="requester"/> when non-null.</summary>
    Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, RequesterRoles? requester, CancellationToken cancellationToken = default);

    /// <summary>As the requester overload, also checking the CA permission rule for <paramref name="caller"/> when non-null.</summary>
    Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates exactly what approval does: the CA permission rule for the approver plus, for a CA-capable
    /// request or a root renewal, the independent-approver rule when <see cref="CaSettings.RequireIndependentCaApproval"/> is set.
    /// A waived self-approval is allowed and flagged on the decision for the audit text.
    /// </summary>
    Task<PolicyDecision> EvaluateApprovalAsync(CertificateRequest request, CaSettings settings, CallerContext? caller, CancellationToken cancellationToken = default);
}

internal sealed class IssuancePolicyService(
    CertificateRequestDbContext db,
    IIssuancePolicyEvaluator evaluator,
    Issuers.IIssuerRegistry? issuers = null) : IIssuancePolicyService
{
    public Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, CancellationToken cancellationToken = default)
        => EvaluateAsync(request, settings, requester: null, cancellationToken);

    public Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, RequesterRoles? requester, CancellationToken cancellationToken = default)
        => EvaluateAsync(request, settings, requester, caller: null, cancellationToken);

    public async Task<PolicyDecision> EvaluateAsync(CertificateRequest request, CaSettings settings, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        if (request.Type == WellKnownCertificateTypes.RootCa)
            return RootCaDecision(request, caller);

        var template = await db.CertificateTemplates
            .AsNoTracking()
            .FirstOrDefaultAsync(t => t.TypeKey == request.Type, cancellationToken);

        IssuancePolicy? policy = null;
        IssuancePolicyVersion? published = null;
        if (template?.IssuancePolicyId is { } policyId)
        {
            policy = await db.IssuancePolicies
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == policyId, cancellationToken);
            published = await db.IssuancePolicyVersions
                .AsNoTracking()
                .FirstOrDefaultAsync(v => v.PolicyId == policyId && v.Status == IssuancePolicyVersionStatus.Published,
                    cancellationToken);
        }

        IReadOnlyList<Issuer>? issuerPath = null;
        if (issuers is not null && template is not null)
        {
            try
            {
                var handle = await issuers.ForIssuanceAsync(template, cancellationToken);
                issuerPath = handle.RecordedIssuerId is { } id ? await issuers.PathForAsync(id, cancellationToken) : null;
            }
            catch (CaNotInitializedException)
            {
                // No usable issuer: EnsureCaAvailableForAsync (create) and the consumer refuse with the CA
                // reason; policy evaluation has nothing issuer-specific to add.
            }
        }

        return evaluator.Evaluate(request, template, policy, published, settings, requester, issuerPath, caller);
    }

    /// <summary>
    /// Root requests have no template or policy. Creating the first root is guarded by onboarding (and replacing a CA
    /// by <c>/v1/ca/generate</c>'s own force check), but a root renewal replaces the trust anchor through the ordinary
    /// renew and approve routes, so it needs <c>certificates.ca</c> like every other CA certificate; protocol callers
    /// never qualify. Before 1.0.0-rc5 any certificate operator could renew and approve the root.
    /// </summary>
    private static PolicyDecision RootCaDecision(CertificateRequest request, CallerContext? caller)
    {
        if (request.RenewedFromId is null || caller is null || caller.MayHandleCaRequests)
            return PolicyDecision.Unrestricted;
        return new PolicyDecision(false, null, null, null,
        [
            new IssuancePolicyViolation(PolicyRules.CaPermission, WellKnownCertificateTypes.RootCa,
                $"Renewing the root CA gives it a new key and makes it the default issuer; requesting or approving it needs the {AppPermissions.CertificatesCa} permission.")
        ]);
    }

    public async Task<PolicyDecision> EvaluateApprovalAsync(CertificateRequest request, CaSettings settings, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        var decision = await EvaluateAsync(request, settings, requester: null, caller, cancellationToken);
        if (caller is null) return decision;

        // A root renewal replaces the trust anchor, so it takes the same second person as a CA-capable template.
        // The first root (no RenewedFromId) stays with onboarding, where one administrator may be all there is.
        bool isCa;
        if (request.Type == WellKnownCertificateTypes.RootCa)
            isCa = request.RenewedFromId is not null;
        else
            isCa = CaCapableTemplate.IsCaCapable(await db.CertificateTemplates.AsNoTracking()
                .FirstOrDefaultAsync(t => t.TypeKey == request.Type, cancellationToken));
        if (!isCa || !IndependentApprovalRule.IsSelfApproval(request, caller))
            return decision;

        if (!settings.RequireIndependentCaApproval)
            return decision with { SelfApprovalWaived = true };

        return decision with
        {
            Allowed = false,
            Violations =
            [
                .. decision.Violations,
                new IssuancePolicyViolation(PolicyRules.SelfApproval, caller.Name,
                    "You filed this request, and a CA certificate must be approved by someone else. " +
                    "An administrator can waive this with 'qca ca approval set waived'.")
            ]
        };
    }
}
