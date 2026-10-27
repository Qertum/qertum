namespace Qertum.Services;

public interface ICertificateRequestService
{
    /// <summary>
    /// One page of requests, optionally narrowed to a single status and to a search over the common
    /// name and requester. Both filters run in the database: the list pages page through the result,
    /// so filtering a single fetched page in the client would silently hide rows past that page.
    /// </summary>
    Task<PagedResult<CertificateRequest>> GetAllAsync(int page = 1, int pageSize = 100,
        CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Number of requests per status, over the same optional search <see cref="GetAllAsync"/> applies.
    /// Counts every matching row rather than the current page, so the list's filter chips stay exact
    /// however many requests exist.
    /// </summary>
    Task<CertificateRequestStatusCounts> GetStatusCountsAsync(string? search = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of issued certificates, optionally narrowed to a validity bucket and a search over
    /// the common name and requester. Both run in the database, for the same reason
    /// <see cref="GetAllAsync"/>'s do.
    /// </summary>
    Task<PagedResult<CertificateRequest>> GetIssuedAsync(int page = 1, int pageSize = 100,
        IssuedCertificateFilter? filter = null, string? search = null, CancellationToken cancellationToken = default);

    /// <summary>Certificate counts per validity bucket, over the same optional search.</summary>
    Task<IssuedCertificateCounts> GetIssuedValidityCountsAsync(string? search = null, CancellationToken cancellationToken = default);

    Task<PagedResult<CertificateRequest>> GetRejectedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default);

    Task<PagedResult<CertificateRequest>> GetRevokedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default);

    Task<PagedResult<CertificateRequest>> GetExpiredAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Every revoked certificate, unpaged, projected to the columns the CRL needs. A CRL must list
    /// all of them: a certificate missing from the CRL is one a relying party treats as valid, so
    /// this deliberately has no page size to cap it.
    /// </summary>
    Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Every revoked certificate whose <see cref="CertificateRequest.RevokedAtUtc"/> is strictly
    /// after <paramref name="sinceUtc"/> — the base CRL's <c>thisUpdate</c> timestamp — projected to
    /// the same columns as <see cref="GetAllRevokedForCrlAsync"/>. Unpaged for the same reason.
    /// </summary>
    Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, CancellationToken cancellationToken = default);

    /// <summary>As <see cref="GetAllRevokedForCrlAsync(CancellationToken)"/>, limited to rows <paramref name="scope"/> owns.</summary>
    Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => GetAllRevokedForCrlAsync(cancellationToken);

    /// <summary>As <see cref="GetRevokedSinceForCrlAsync(DateTime, CancellationToken)"/>, limited to rows <paramref name="scope"/> owns.</summary>
    Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => GetRevokedSinceForCrlAsync(sinceUtc, cancellationToken);

    Task<CertificateRequest?> GetByIdAsync(CertificateRequestId id, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> DequeueNextApprovedAsync(CancellationToken cancellationToken = default);

    Task<int> ResetStuckProcessingAsync(CancellationToken cancellationToken = default);

    Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a request. <paramref name="autoApprovalSetting"/> names the setting that inserted it
    /// already Approved (e.g. <c>AcmeAutoApprove</c>); it only words the <c>Approved</c> audit entry.
    /// </summary>
    Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a request. <paramref name="requester"/> is the submitting caller's IdP roles for a
    /// REST create (checked against the policy's requester roles); null for ACME, EST and renewals.
    /// </summary>
    Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, Policies.RequesterRoles? requester, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a request. <paramref name="caller"/> is non-null for a human or protocol submission;
    /// null skips the CA permission rule (internal callers only).
    /// </summary>
    Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, Policies.RequesterRoles? requester, Policies.CallerContext? caller, CancellationToken cancellationToken = default);

    /// <summary>Approves, recording in the audit what the approver's client reported its preview showed.</summary>
    Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Policies.ApprovalPreviewReport? previewReport, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Approves on behalf of <paramref name="caller"/>, also enforcing the CA permission and the
    /// independent-approver rule. A null caller skips both (internal callers only).
    /// </summary>
    Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Policies.ApprovalPreviewReport? previewReport, Policies.CallerContext? caller, CancellationToken cancellationToken);

    /// <summary>Approves a request through a named automatic setting, without claiming a client preview.</summary>
    Task<CertificateRequest?> MarkAsAutoApprovedAsync(CertificateRequestId id, string performedBy,
        string autoApprovalSetting, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsRejectedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsRejectedWithReasonAsync(CertificateRequestId id, string? failureReason, string performedBy, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsIssuedAsync(CertificateRequestId id, GeneratedCertificate generatedData, string performedBy = "queue-consumer", CancellationToken cancellationToken = default);

    /// <summary>
    /// Re-evaluates a claimed request against its template's current published policy immediately
    /// before signing. Allowed: records the governing version and returns. Violation: rejects the
    /// request with a <see cref="CertificateRequest.FailureReason"/> and returns the decision — the
    /// caller must not sign.
    /// </summary>
    Task<Policies.PolicyDecision> CheckIssuancePolicyAsync(CertificateRequestId id, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsPendingRevocationAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> DequeueNextPendingRevocationAsync(CancellationToken cancellationToken = default);

    Task<CertificateRequest?> MarkAsRevokedAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>Replaces the metadata set of a request; null when no request has that id. No-op edits write nothing.</summary>
    Task<CertificateRequest?> UpdateMetadataAsync(CertificateRequestId id, CertificateMetadata metadata, string performedBy, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>Renews a request. <paramref name="caller"/> is non-null for a human submission; null skips the CA permission rule.</summary>
    Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, Policies.CallerContext? caller, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<CertificateRequest>> GetCertsNeedingAutoRenewalAsync(int daysBeforeExpiry, CancellationToken cancellationToken = default);

    Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>Updates a request, checking the editing caller's roles when <paramref name="requester"/> is non-null.</summary>
    Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, Policies.RequesterRoles? requester, CancellationToken cancellationToken = default);

    /// <summary>Updates a request. <paramref name="caller"/> is non-null for a human submission; null skips the CA permission rule.</summary>
    Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, Policies.RequesterRoles? requester, Policies.CallerContext? caller, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default);

    Task<CertificateDashboardSummary> GetDashboardSummaryAsync(CancellationToken cancellationToken = default);

    Task<CaSettings> GetSettingsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets the CA-wide default PQC stage. Audited as <c>PqcStageChanged</c>; a no-op writes nothing.
    /// Callers must have checked the admin role: loosening enforcement is not a grantable permission.
    /// </summary>
    Task<CaSettings> SetPqcStageAsync(PqcStage stage, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets what happens when a certificate's key claims a higher NIST level than its issuer's. Audited as
    /// <c>IssuerStrengthChanged</c>; a no-op writes nothing. Callers must have checked the admin role.
    /// </summary>
    Task<CaSettings> SetIssuerStrengthAsync(IssuerStrengthMode mode, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets what happens when an issuer's own certificate is revoked. Audited as
    /// <c>RevokedIssuerModeChanged</c>; a no-op writes nothing. Callers must have checked the admin role.
    /// </summary>
    Task<CaSettings> SetRevokedIssuerModeAsync(RevokedIssuerMode mode, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets whether CA-capable requests need a different approver than their requester. Audited as
    /// <c>CaApprovalRuleChanged</c>; a no-op writes nothing. Callers must have checked the admin role.
    /// </summary>
    Task<CaSettings> SetCaApprovalRuleAsync(bool requireIndependent, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Turns two-person approval of sensitive operations on or off. Audited as <c>TwoPersonApprovalChanged</c>;
    /// a no-op writes nothing. Callers must have checked the admin role.
    /// </summary>
    Task<CaSettings> SetTwoPersonApprovalAsync(bool enabled, string performedBy, CancellationToken cancellationToken = default);

    Task<CaSettings> SetupOrUpdateSettingsAsync(CaSettings settings, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically increments and returns the CRL number, so two API instances publishing at the same
    /// moment cannot issue two different CRLs under one number.
    /// </summary>
    /// <summary>
    /// Revocation status for the given serial numbers (uppercase hex, as stored). Serials with no
    /// matching row are absent from the result — the OCSP responder reports those as unknown rather
    /// than good, so a serial this CA never issued is never vouched for.
    /// </summary>
    Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, CancellationToken cancellationToken = default);

    /// <summary>As the unscoped overload, answering only for rows <paramref name="scope"/> owns (other serials are absent, i.e. unknown).</summary>
    Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => GetRevocationStatusesAsync(serialNumbers, cancellationToken);

    Task<long> ClaimNextCrlNumberAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Records <paramref name="crlNumber"/> and <paramref name="thisUpdateUtc"/> as the current delta
    /// CRL base (<see cref="CaSettings.BaseCrlNumber"/> / <see cref="CaSettings.BaseCrlThisUpdateUtc"/>),
    /// called by the full-CRL endpoint every time it regenerates.
    /// </summary>
    Task RecordBaseCrlAsync(long crlNumber, DateTime thisUpdateUtc, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the ID of the first <see cref="WellKnownCertificateTypes.RootCa"/> request in a
    /// pre-issuance state (Pending, Approved, or Processing), or <see langword="null"/> when none exists.
    /// </summary>
    Task<Guid?> GetPendingRootCaRequestIdAsync(CancellationToken cancellationToken = default);
}
