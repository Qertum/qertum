using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services.Policies;

namespace Qertum.Services;

internal sealed class CertificateRequestDeletionConflictException(CertificateRequestStatus status)
    : InvalidOperationException($"Cannot delete a certificate request with status '{status}'.")
{
}

public sealed class CertificateRequestService(
    CertificateRequestDbContext dbContext,
    IAuditLogService auditLog,
    IWebhookService webhookService,
    IIssuancePolicyService issuancePolicy,
    // Optional so the many test scopes that construct this service directly stay valid; every host
    // registers ICertificateGenerator in the same AddCustomCaServices call that registers this
    // service, so in a running deployment it is always present.
    ICertificateGenerator? certificateGenerator = null,
    Issuers.IIssuerRegistry? issuerRegistry = null,
    IPqcStageService? pqcStage = null,
    TimeProvider? timeProvider = null,
    // Takes an issuer out of service when its own certificate is revoked. Optional like the registry above.
    Issuers.IssuerRevocationService? issuerRevocation = null) : ICertificateRequestService
{
    // Optional like the generator: tests that construct this directly keep compiling, and get the
    // same stage rules a host would.
    private readonly IPqcStageService _pqcStage = pqcStage ?? new PqcStageService(dbContext, null, timeProvider);

    private async Task<PqcVerdict> EvaluatePqcAsync(CertificateRequest request, CertificateKeyAlgorithm algorithm,
        bool isRenewal, PolicyEnforcementStage stage, string? renewalHint, CancellationToken cancellationToken)
    {
        var verdict = await _pqcStage.EvaluateAsync(PqcContext.FromRequest(request, algorithm, isRenewal), cancellationToken);
        if (verdict.Outcome == PqcOutcome.Refused)
            throw new PqcPolicyViolationException(
                renewalHint is null ? verdict.Reason! : $"{verdict.Reason} {renewalHint}", stage);
        return verdict;
    }

    private static void AttachWarnings(CertificateRequest request, PqcVerdict verdict, PolicyDecision decision)
    {
        var warnings = new List<string>();
        if (verdict.Outcome == PqcOutcome.AllowedWithWarning && verdict.Reason is not null) warnings.Add(verdict.Reason);
        warnings.AddRange(decision.Warnings);
        request.Warnings = warnings.Count == 0 ? null : warnings;
    }

    // Time is read through TimeProvider so expiry and scheduling can be tested with a fake clock;
    // optional so code that constructs this directly keeps compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Refuses a request that could never be signed. The approve endpoint and the queue consumer both
    /// check this too, but only after a row exists: without this, a request filed before the root CA
    /// is approved sits Pending until someone tries to approve it, and an auto-approving protocol
    /// (ACME, EST) burns the consumer's retries before being rejected. Root CA requests are exempt —
    /// approving one is what creates the CA.
    /// </summary>
    private async Task EnsureCaAvailableForAsync(CertificateRequest request, CancellationToken ct)
    {
        if (request.Type == WellKnownCertificateTypes.RootCa) return;
        if (issuerRegistry is not null)
        {
            var template = await dbContext.CertificateTemplates.AsNoTracking()
                .FirstOrDefaultAsync(t => t.TypeKey == request.Type, ct);
            // Throws CaNotInitializedException, or IssuerNotActiveException for a pin that cannot sign.
            await issuerRegistry.ForIssuanceAsync(template, ct);
            return;
        }
        if (certificateGenerator is null || certificateGenerator.IsInitialized) return;
        throw new CaNotInitializedException();
    }

    public async Task<PagedResult<CertificateRequest>> GetAllAsync(int page = 1, int pageSize = 100,
        CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Clamp(page, pageSize);
        var query = ApplyListFilters(dbContext.CertificateRequests, status, search)
            .OrderByDescending(r => r.CreatedAtUtc)
            .ThenBy(r => r.Id);
        return await ToPagedResultAsync(query, page, pageSize, cancellationToken);
    }

    public async Task<CertificateRequestStatusCounts> GetStatusCountsAsync(string? search = null, CancellationToken cancellationToken = default)
    {
        var counts = await ApplyListFilters(dbContext.CertificateRequests, status: null, search)
            .GroupBy(r => r.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToListAsync(cancellationToken);

        return new CertificateRequestStatusCounts
        {
            ByStatus = counts.ToDictionary(c => c.Status.ToString(), c => c.Count),
            Total = counts.Sum(c => c.Count)
        };
    }

    /// <summary>
    /// The status and search filters shared by the list page and its chip counts, so a count can
    /// never disagree with the list it labels.
    /// </summary>
    private static IQueryable<CertificateRequest> ApplyListFilters(
        IQueryable<CertificateRequest> query, CertificateRequestStatus? status, string? search)
    {
        if (status is { } wanted)
            query = query.Where(r => r.Status == wanted);

        var term = search?.Trim();
        if (string.IsNullOrEmpty(term)) return query;

        // SQLite's LIKE is case-insensitive for ASCII, which is the behaviour the browser-side
        // OrdinalIgnoreCase filter this replaced had.
        var pattern = $"%{EscapeLikePattern(term)}%";
        // The contact email is deliberately not searched: it is personal data kept for notifications.
        return query.Where(r => EF.Functions.Like(r.CommonName, pattern, LikeEscape)
                             || EF.Functions.Like(r.RequestedBy, pattern, LikeEscape)
                             || (r.Metadata.OwnerTeam != null && EF.Functions.Like(r.Metadata.OwnerTeam, pattern, LikeEscape))
                             || (r.Metadata.TargetSystem != null && EF.Functions.Like(r.Metadata.TargetSystem, pattern, LikeEscape))
                             || (r.Metadata.TicketReference != null && EF.Functions.Like(r.Metadata.TicketReference, pattern, LikeEscape)));
    }

    private const string LikeEscape = "\\";

    /// <summary>
    /// Escapes the LIKE metacharacters so a search term is matched literally — a common name
    /// containing <c>_</c> or <c>%</c> must not be searched as a wildcard pattern.
    /// </summary>
    private static string EscapeLikePattern(string value) =>
        value.Replace(LikeEscape, LikeEscape + LikeEscape)
             .Replace("%", LikeEscape + "%")
             .Replace("_", LikeEscape + "_");

    public async Task<PagedResult<CertificateRequest>> GetIssuedAsync(int page = 1, int pageSize = 100,
        IssuedCertificateFilter? filter = null, string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Clamp(page, pageSize);
        var source = validOnly ? await ValidCertificatesAsync(cancellationToken) : IssuedCertificates();
        var query = ApplyIssuedFilters(source, filter, search)
            .OrderByDescending(r => r.ValidFrom)
            .ThenBy(r => r.Id);
        return await ToPagedResultAsync(query, page, pageSize, cancellationToken);
    }

    public async Task<IssuedCertificateCounts> GetIssuedValidityCountsAsync(string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
    {
        var counted = new Dictionary<string, int>();
        var total = 0;
        var source = validOnly ? await ValidCertificatesAsync(cancellationToken) : IssuedCertificates();

        // One query per bucket rather than a grouped projection: the buckets are date comparisons
        // against "now", not a stored column, so there is nothing to group by.
        foreach (var filter in Enum.GetValues<IssuedCertificateFilter>())
        {
            var count = await ApplyIssuedFilters(source, filter, search).CountAsync(cancellationToken);
            if (count > 0) counted[filter.ToString()] = count;
            total += count;
        }

        return new IssuedCertificateCounts { ByFilter = counted, Total = total };
    }

    private IQueryable<CertificateRequest> IssuedCertificates() =>
        dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Issued
                     || r.Status == CertificateRequestStatus.Revoked
                     || r.Status == CertificateRequestStatus.PendingRevocation);

    /// <summary>
    /// "Show only valid": issued, not expired, and under no revoked or expired CA (<see cref="Issuers.IssuerQueries.Broken"/>).
    /// A renewed original stays until it expires, so the overlap with its renewal shows.
    /// </summary>
    private async Task<IQueryable<CertificateRequest>> ValidCertificatesAsync(CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var (broken, legacyBroken) = await Issuers.IssuerQueries.BrokenAsync(dbContext, now, cancellationToken);
        var brokenIds = broken.Select(id => (IssuerId?)id).ToList();
        return dbContext.CertificateRequests.Where(r =>
            r.Status == CertificateRequestStatus.Issued
            && (r.ValidTo == null || r.ValidTo > now)
            && (r.IssuerId == null ? !legacyBroken : !brokenIds.Contains(r.IssuerId)));
    }

    /// <summary>
    /// The validity-bucket and search filters shared by the certificates list and its chip counts.
    /// The buckets are mutually exclusive and together cover every issued certificate, so the chips
    /// always add up to the total.
    /// </summary>
    private IQueryable<CertificateRequest> ApplyIssuedFilters(
        IQueryable<CertificateRequest> query, IssuedCertificateFilter? filter, string? search)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var soon = now.AddDays(IssuedCertificateCounts.ExpiringWindowDays);

        query = filter switch
        {
            IssuedCertificateFilter.Revoked => query.Where(r => r.Status == CertificateRequestStatus.Revoked),
            IssuedCertificateFilter.Revoking => query.Where(r => r.Status == CertificateRequestStatus.PendingRevocation),
            IssuedCertificateFilter.Expired => query.Where(r => r.Status == CertificateRequestStatus.Issued
                                                             && r.ValidTo != null && r.ValidTo <= now),
            IssuedCertificateFilter.Expiring => query.Where(r => r.Status == CertificateRequestStatus.Issued
                                                              && r.ValidTo != null && r.ValidTo > now && r.ValidTo <= soon),
            // A certificate with no ValidTo has nothing to expire, so it reads as valid.
            IssuedCertificateFilter.Valid => query.Where(r => r.Status == CertificateRequestStatus.Issued
                                                           && (r.ValidTo == null || r.ValidTo > soon)),
            _ => query
        };

        return ApplyListFilters(query, status: null, search);
    }

    public async Task<PagedResult<CertificateRequest>> GetRejectedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Clamp(page, pageSize);
        var query = dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Rejected)
            .OrderByDescending(r => r.UpdatedAtUtc)
            .ThenBy(r => r.Id);
        return await ToPagedResultAsync(query, page, pageSize, cancellationToken);
    }

    public async Task<PagedResult<CertificateRequest>> GetRevokedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Clamp(page, pageSize);
        var query = dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Revoked)
            .OrderByDescending(r => r.RevokedAtUtc)
            .ThenBy(r => r.Id);
        return await ToPagedResultAsync(query, page, pageSize, cancellationToken);
    }

    /// <inheritdoc />
    private IQueryable<CertificateRequest> InScope(Issuers.IssuerScope scope) =>
        dbContext.CertificateRequests.Where(r =>
            r.IssuerId == scope.IssuerId || (scope.IncludesUnassigned && r.IssuerId == null));

    public Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(CancellationToken cancellationToken = default)
        => RevokedForCrlAsync(dbContext.CertificateRequests, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => RevokedForCrlAsync(InScope(scope), cancellationToken);

    private static async Task<IReadOnlyList<CertificateRequest>> RevokedForCrlAsync(IQueryable<CertificateRequest> source, CancellationToken cancellationToken)
    {
        // Only the columns GenerateCrl reads. No private-key columns, no PropertiesJson: the CRL
        // build touches every revoked row, so anything extra is decrypted and materialised for
        // nothing.
        return await source
            .AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Revoked)
            .OrderBy(r => r.RevokedAtUtc)
            .ThenBy(r => r.Id)
            .Select(r => new CertificateRequest
            {
                Id = r.Id,
                CommonName = r.CommonName,
                Status = r.Status,
                CertificatePem = r.CertificatePem,
                PqcCertificatePem = r.PqcCertificatePem,
                RevokedAtUtc = r.RevokedAtUtc,
                RevocationReason = r.RevocationReason
            })
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, CancellationToken cancellationToken = default)
        => RevokedSinceForCrlAsync(dbContext.CertificateRequests, sinceUtc, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => RevokedSinceForCrlAsync(InScope(scope), sinceUtc, cancellationToken);

    private static async Task<IReadOnlyList<CertificateRequest>> RevokedSinceForCrlAsync(IQueryable<CertificateRequest> source, DateTime sinceUtc, CancellationToken cancellationToken)
    {
        return await source
            .AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Revoked && r.RevokedAtUtc != null && r.RevokedAtUtc > sinceUtc)
            .OrderBy(r => r.RevokedAtUtc)
            .ThenBy(r => r.Id)
            .Select(r => new CertificateRequest
            {
                Id = r.Id,
                CommonName = r.CommonName,
                Status = r.Status,
                CertificatePem = r.CertificatePem,
                PqcCertificatePem = r.PqcCertificatePem,
                RevokedAtUtc = r.RevokedAtUtc,
                RevocationReason = r.RevocationReason
            })
            .ToListAsync(cancellationToken);
    }

    public async Task<PagedResult<CertificateRequest>> GetExpiredAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        (page, pageSize) = Clamp(page, pageSize);
        var now = _clock.GetUtcNow().UtcDateTime;
        var query = dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo != null && r.ValidTo <= now)
            .OrderByDescending(r => r.ValidTo)
            .ThenBy(r => r.Id);
        return await ToPagedResultAsync(query, page, pageSize, cancellationToken);
    }

    private static (int page, int pageSize) Clamp(int page, int pageSize) =>
        (Math.Max(1, page), Math.Clamp(pageSize, 1, 500));

    /// <summary>
    /// Projects a request without its private-key columns. List responses never carry key material
    /// (<c>[JsonIgnore]</c> on the entity is the backstop), so reading and decrypting those columns
    /// for every row on every page is pure cost. Keys are served only by the owner-gated
    /// private-key endpoint, which loads the full entity for a single row.
    /// </summary>
    private static IQueryable<CertificateRequest> WithoutPrivateKeys(IQueryable<CertificateRequest> query) =>
        query.Select(r => new CertificateRequest
        {
            Id = r.Id,
            CommonName = r.CommonName,
            RequestedBy = r.RequestedBy,
            RequestedBySubject = r.RequestedBySubject,
            Status = r.Status,
            CreatedAtUtc = r.CreatedAtUtc,
            UpdatedAtUtc = r.UpdatedAtUtc,
            ValidFrom = r.ValidFrom,
            ValidTo = r.ValidTo,
            RevokedAtUtc = r.RevokedAtUtc,
            Type = r.Type,
            PropertiesJson = r.PropertiesJson,
            CertificatePem = r.CertificatePem,
            SerialNumber = r.SerialNumber,
            PqcSerialNumber = r.PqcSerialNumber,
            RevocationReason = r.RevocationReason,
            RenewedFromId = r.RenewedFromId,
            KeyAlgorithm = r.KeyAlgorithm,
            ValidityDays = r.ValidityDays,
            PqcCertificatePem = r.PqcCertificatePem,
            FailureReason = r.FailureReason,
            CsrPem = r.CsrPem,
            // Presence flags, so clients can offer a download without the key being serialized.
            // MarkAsIssuedAsync normalizes an empty key to NULL, so a null check is sufficient.
            HasPrivateKey = r.PrivateKeyPem != null,
            HasPqcPrivateKey = r.PqcPrivateKeyPem != null,
            Metadata = r.Metadata
        });

    private static async Task<PagedResult<CertificateRequest>> ToPagedResultAsync(
        IQueryable<CertificateRequest> query, int page, int pageSize, CancellationToken cancellationToken)
    {
        var items = await WithoutPrivateKeys(query)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        // Skip the COUNT query only on page 1 when we got fewer items than the page size —
        // that definitively means there are no more pages, so count == items returned.
        int totalCount;
        if (page == 1 && items.Count < pageSize)
            totalCount = items.Count;
        else
            totalCount = await query.CountAsync(cancellationToken);

        return new PagedResult<CertificateRequest>
        {
            Items = items,
            TotalCount = totalCount,
            Page = page,
            PageSize = pageSize
        };
    }

    public async Task<CertificateRequest?> GetByIdAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var request = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(request => request.Id == id, cancellationToken);

        if (request is not null)
        {
            // Key material is suppressed at serialization; the flags are what reaches the client.
            // This entity is also the one the private-key endpoint reads the key from, so the
            // properties themselves are deliberately left populated here.
            request.HasPrivateKey = !string.IsNullOrEmpty(request.PrivateKeyPem);
            request.HasPqcPrivateKey = !string.IsNullOrEmpty(request.PqcPrivateKeyPem);
        }

        return request;
    }

    public async Task<int> ResetStuckProcessingAsync(CancellationToken cancellationToken = default)
    {
        return await dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Processing)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, CertificateRequestStatus.Approved)
                .SetProperty(r => r.UpdatedAtUtc, _clock.GetUtcNow().UtcDateTime),
                cancellationToken);
    }

    /// <summary>
    /// Refreshes a row this context may already be tracking after an <c>ExecuteUpdateAsync</c> claim.
    /// The claim writes straight to the database, so a tracked instance keeps its pre-claim snapshot
    /// and every later read of that row in the same scope — EF resolves those from the identity map,
    /// not the database — would see the old status and gate on it. Returns the refreshed instance, or
    /// null when the row was not tracked here.
    /// </summary>
    private async Task<CertificateRequest?> RefreshTrackedAsync(CertificateRequestId id, CancellationToken cancellationToken)
    {
        var tracked = dbContext.CertificateRequests.Local.FirstOrDefault(r => r.Id == id);
        if (tracked is null) return null;

        await dbContext.Entry(tracked).ReloadAsync(cancellationToken);
        return tracked;
    }

    public async Task<CertificateRequest?> DequeueNextApprovedAsync(CancellationToken cancellationToken = default)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            // AsNoTracking is load-bearing: the claim below goes through ExecuteUpdateAsync, which
            // writes straight to the database and leaves the change tracker holding the pre-claim
            // snapshot. A tracked row would keep the hand-patched Status queued as a pending
            // modification, and the next SaveChangesAsync in this scope would write it back over
            // whatever the row has since become.
            var next = await dbContext.CertificateRequests
                .AsNoTracking()
                .Where(request => request.Status == CertificateRequestStatus.Approved)
                .OrderBy(request => request.UpdatedAtUtc)
                .ThenBy(request => request.Id)
                .FirstOrDefaultAsync(cancellationToken);

            if (next == null) return null;

            var rowsAffected = await dbContext.CertificateRequests
                .Where(r => r.Id == next.Id && r.Status == CertificateRequestStatus.Approved)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(r => r.Status, CertificateRequestStatus.Processing)
                    .SetProperty(r => r.UpdatedAtUtc, _clock.GetUtcNow().UtcDateTime),
                    cancellationToken);

            if (rowsAffected == 0) continue;

            var claimed = await RefreshTrackedAsync(next.Id, cancellationToken);
            if (claimed is not null) next = claimed;

            // Detached, so this only shapes the returned value — nothing is queued for a later write.
            next.Status = CertificateRequestStatus.Processing;
            await auditLog.LogAsync("IssuanceQueued", "queue-consumer", (Guid)next.Id, next.CommonName,
                cancellationToken: cancellationToken);
            return next;
        }
        return null;
    }

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => MarkAsApprovedAsync(id, performedBy, previewReport: null, cancellationToken);

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, ApprovalPreviewReport? previewReport, CancellationToken cancellationToken = default)
        => ApproveAsync(id, performedBy, previewReport, autoApprovalSetting: null, caller: null, cancellationToken);

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, ApprovalPreviewReport? previewReport, CallerContext? caller, CancellationToken cancellationToken)
        => ApproveAsync(id, performedBy, previewReport, autoApprovalSetting: null, caller, cancellationToken);

    public Task<CertificateRequest?> MarkAsAutoApprovedAsync(CertificateRequestId id, string performedBy,
        string autoApprovalSetting, CancellationToken cancellationToken = default)
        => ApproveAsync(id, performedBy, previewReport: null, autoApprovalSetting, caller: null, cancellationToken);

    private async Task<CertificateRequest?> ApproveAsync(CertificateRequestId id, string performedBy,
        ApprovalPreviewReport? previewReport, string? autoApprovalSetting, CallerContext? caller, CancellationToken cancellationToken)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);

        if (existing is null || existing.Status != CertificateRequestStatus.Pending)
            return null;

        // Re-checked against the latest published version: the policy may have tightened since the
        // request was created. The violation throws before anything is saved, so the request stays
        // Pending for a human to reject, or for a later policy change to make approvable.
        var settings = await GetSettingsAsync(cancellationToken);
        try
        {
            await EvaluatePqcAsync(existing, existing.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa,
                isRenewal: existing.RenewedFromId is not null, PolicyEnforcementStage.Approval, renewalHint: null, cancellationToken);
        }
        catch (PqcPolicyViolationException ex)
        {
            await auditLog.LogAsync("ApprovalBlockedByPolicy", performedBy, (Guid)id, existing.CommonName,
                $"PQC stage: {ex.Message}", cancellationToken);
            throw;
        }
        var createdUnder = await PolicyVersionLookup.FindAsync(dbContext, existing.PolicyVersionId, cancellationToken);
        var policyDecision = await issuancePolicy.EvaluateApprovalAsync(existing, settings, caller, cancellationToken);
        var reportedVersion = previewReport is null
            ? null
            : await PolicyVersionLookup.FindAsync(dbContext, previewReport.PolicyVersionId, cancellationToken);
        var reported = previewReport is null
            ? null
            : new ReportedPreview(
                previewReport.Allowed,
                previewReport.PolicyVersionId,
                reportedVersion?.Number,
                reportedVersion?.PolicyName,
                previewReport.PolicyVersionId == policyDecision.PolicyVersionId);

        if (!policyDecision.Allowed)
        {
            await auditLog.LogAsync("ApprovalBlockedByPolicy", performedBy, (Guid)id, existing.CommonName,
                autoApprovalSetting is null
                    ? ApprovalAuditDetail.ForBlockedApproval(policyDecision, createdUnder, reported)
                    : ApprovalAuditDetail.ForBlockedAutoApproval(autoApprovalSetting, policyDecision, createdUnder),
                cancellationToken);
            throw new IssuancePolicyViolationException(policyDecision, PolicyEnforcementStage.Approval);
        }

        existing.Status = CertificateRequestStatus.Approved;
        RecordPolicyDecision(existing, policyDecision);
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("Approved", performedBy, (Guid)id, existing.CommonName,
            autoApprovalSetting is null
                ? ApprovalAuditDetail.ForApproval(policyDecision, createdUnder, reported)
                : ApprovalAuditDetail.ForAutoApproval(autoApprovalSetting, policyDecision, createdUnder),
            cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Approved, existing, performedBy), cancellationToken);

        if (!existing.RenewedFromId.HasValue)
            return existing;

        // Not for a root: revoking it would retire everything it signed. Signing the renewal retires it instead
        // (IssuanceSigner), and its certificates stay checkable.
        if (settings.AutoRevokeOnRenewal && existing.Type != WellKnownCertificateTypes.RootCa)
            await MarkAsPendingRevocationAsync(existing.RenewedFromId.Value, "superseded", performedBy, cancellationToken);

        return existing;
    }

    public Task<CertificateRequest?> MarkAsRejectedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => MarkAsRejectedWithReasonAsync(id, null, performedBy, cancellationToken);

    public async Task<CertificateRequest?> MarkAsRejectedWithReasonAsync(CertificateRequestId id, string? failureReason, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);

        // Allow rejecting both Pending (human rejection) and Processing (queue consumer failure)
        if (existing is null ||
            (existing.Status != CertificateRequestStatus.Pending &&
             existing.Status != CertificateRequestStatus.Processing))
            return null;

        existing.Status = CertificateRequestStatus.Rejected;
        existing.FailureReason = failureReason;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("Rejected", performedBy, (Guid)id, existing.CommonName,
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Rejected, existing, performedBy), cancellationToken);

        return existing;
    }

    /// <summary>
    /// Whether this failed save is the active-common-name index rejecting a duplicate. SQLite names
    /// the table and column in the message rather than the index, so both spellings are matched.
    /// </summary>
    private static bool IsActiveCommonNameConflict(DbUpdateException ex)
    {
        var message = ex.InnerException?.Message;
        return message is not null &&
               (message.Contains(CertificateRequestDbContext.ActiveCommonNameIndexName, StringComparison.Ordinal) ||
                message.Contains("CertificateRequests.CommonName", StringComparison.Ordinal));
    }

    // Internal callers (root CA requests): no caller, so the CA permission rule is skipped.
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, CancellationToken cancellationToken = default)
        => CreateAsync(request, performedBy, autoApprovalSetting: null, requester: null, caller: null, cancellationToken);

    // Only ACME and EST use this overload: they are protocol submissions, which never issue a CA certificate.
    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, CancellationToken cancellationToken = default)
        => CreateAsync(request, performedBy, autoApprovalSetting, requester: null, CallerContext.Protocol, cancellationToken);

    public Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, RequesterRoles? requester, CancellationToken cancellationToken = default)
        => CreateAsync(request, performedBy, autoApprovalSetting, requester, caller: null, cancellationToken);

    public async Task<CertificateRequest> CreateAsync(CertificateRequest request, string performedBy, string? autoApprovalSetting, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        await EnsureCaAvailableForAsync(request, cancellationToken);

        var settings = await GetSettingsAsync(cancellationToken);
        var effectiveAlgorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        var pqcVerdict = await EvaluatePqcAsync(request, effectiveAlgorithm,
            isRenewal: request.RenewedFromId is not null, PolicyEnforcementStage.Create, renewalHint: null, cancellationToken);

        // Covers REST create, ACME finalize and both EST routes, including their auto-approve inserts.
        var policyDecision = await EnforcePolicyAsync(request, settings, PolicyEnforcementStage.Create,
            resourceId: null, performedBy, requester, caller, cancellationToken);

        // Root CA requests are unique by type, not by CN, and a renewal deliberately reuses the CN
        // of the certificate it replaces — both carve-outs live in ActiveCommonNameRule.Applies and
        // must match IX_CertificateRequests_CommonName_Active exactly. Shared with
        // CertificateRequestPreviewService so a preview cannot disagree with the create it predicts.
        if (ActiveCommonNameRule.Applies(request) &&
            await ActiveCommonNameRule.IsTakenAsync(dbContext, request.CommonName, cancellationToken))
        {
            throw new DuplicateRequestException(request.CommonName);
        }

        var entry = new CertificateRequest
        {
            Id = request.Id == default ? Guid.NewGuid() : request.Id,
            CommonName = request.CommonName,
            RequestedBy = request.RequestedBy,
            RequestedBySubject = request.RequestedBySubject,
            Type = request.Type,
            PropertiesJson = request.PropertiesJson,
            Status = request.Status,
            KeyAlgorithm = request.KeyAlgorithm,
            ValidityDays = request.ValidityDays,
            Metadata = request.Metadata with { },
            CsrPem = request.CsrPem,
            // Carried so a caller that already knows which certificate it is replacing — ACME
            // finalize, which sees a repeat order for a domain it has issued before — records the
            // back-pointer. It is not on Create/UpdateCertificateRequestRequest, so this stays
            // unreachable over REST; RenewAsync sets it on the row it inserts itself.
            RenewedFromId = request.RenewedFromId,
            PolicyVersionId = policyDecision.PolicyVersionId,
            PolicyEvaluatedAtUtc = policyDecision.PolicyVersionId is null ? null : _clock.GetUtcNow().UtcDateTime,
            CreatedAtUtc = request.CreatedAtUtc == default ? _clock.GetUtcNow().UtcDateTime : request.CreatedAtUtc,
            UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime
        };

        dbContext.CertificateRequests.Add(entry);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (IsActiveCommonNameConflict(ex))
        {
            // The check above reads before this writes, so a concurrent create can land in between.
            // The index catches that; surface it as the same error the check produces rather than
            // letting a raw constraint violation reach the caller as a 500.
            dbContext.Entry(entry).State = EntityState.Detached;
            throw new DuplicateRequestException(request.CommonName);
        }

        _pqcStage.Record(pqcVerdict, (Guid)entry.Id, performedBy);
        AttachWarnings(entry, pqcVerdict, policyDecision);

        await auditLog.LogAsync("Created", performedBy, (Guid)entry.Id, entry.CommonName,
            RequesterRoleAuditDetail(policyDecision), cancellationToken);
        // ACME/EST auto-approval inserts the row already Approved; without this line no Approved entry exists for it.
        if (entry.Status == CertificateRequestStatus.Approved)
            await auditLog.LogAsync("Approved", performedBy, (Guid)entry.Id, entry.CommonName,
                ApprovalAuditDetail.ForAutoApproval(autoApprovalSetting ?? "auto-approval", policyDecision), cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Created, entry, performedBy), cancellationToken);

        return entry;
    }

    public async Task<CertificateRequest?> MarkAsIssuedAsync(CertificateRequestId id, GeneratedCertificate generatedData, string performedBy = "queue-consumer", CancellationToken cancellationToken = default)
    {
        var existingRequest = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(certificateRequest => certificateRequest.Id == id, cancellationToken);

        if (existingRequest is null)
        {
            return null;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        existingRequest.Status = CertificateRequestStatus.Issued;
        existingRequest.UpdatedAtUtc = now;
        existingRequest.ValidFrom = generatedData.ValidFrom;
        existingRequest.ValidTo = generatedData.ValidTo;
        existingRequest.CertificatePem = generatedData.CertificatePem;
        // Unique-indexed: a duplicate serial fails this save rather than being issued twice.
        existingRequest.SerialNumber = string.IsNullOrEmpty(generatedData.SerialNumber) ? null : generatedData.SerialNumber;
        existingRequest.PqcSerialNumber = string.IsNullOrEmpty(generatedData.PqcSerialNumber) ? null : generatedData.PqcSerialNumber;
        existingRequest.PrivateKeyPem = string.IsNullOrEmpty(generatedData.PrivateKeyPem) ? null : generatedData.PrivateKeyPem;
        existingRequest.PqcCertificatePem = generatedData.PqcCertificatePem;
        existingRequest.PqcPrivateKeyPem = generatedData.PqcPrivateKeyPem;
        existingRequest.IssuerId = generatedData.IssuerId;

        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("Issued", performedBy, (Guid)id, existingRequest.CommonName,
            $"Valid from {generatedData.ValidFrom:yyyy-MM-dd} to {generatedData.ValidTo:yyyy-MM-dd}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Issued, existingRequest, performedBy), cancellationToken);

        return existingRequest;
    }


    public async Task<PolicyDecision> CheckIssuancePolicyAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var claimed = await dbContext.CertificateRequests
                          .SingleOrDefaultAsync(r => r.Id == id, cancellationToken)
                      ?? throw new NotFoundException($"Certificate request {id} was not found.");

        var pqcVerdict = await _pqcStage.EvaluateAsync(
            PqcContext.FromRequest(claimed, claimed.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa, claimed.RenewedFromId is not null),
            cancellationToken);
        if (pqcVerdict.Outcome == PqcOutcome.Refused)
        {
            await auditLog.LogAsync("PolicyRejected", "queue-consumer", (Guid)id, claimed.CommonName,
                $"Stage: {PolicyEnforcementStage.Issuance}. {pqcVerdict.Reason}", cancellationToken);
            await MarkAsRejectedWithReasonAsync(id, $"Rejected by PQC stage before signing. {pqcVerdict.Reason}",
                "queue-consumer", cancellationToken);
            return new PolicyDecision(false, null, null, null,
                [new IssuancePolicyViolation(PolicyRules.PqcOnly,
                    (claimed.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa).ToCanonicalString(), pqcVerdict.Reason!)]);
        }

        var settings = await GetSettingsAsync(cancellationToken);
        var decision = await issuancePolicy.EvaluateAsync(claimed, settings, cancellationToken);

        if (decision.Allowed)
        {
            RecordPolicyDecision(claimed, decision);
            await dbContext.SaveChangesAsync(cancellationToken);
            return decision;
        }

        await auditLog.LogAsync("PolicyRejected", "queue-consumer", (Guid)id, claimed.CommonName,
            $"Stage: {PolicyEnforcementStage.Issuance}. {decision.Summarize()}", cancellationToken);
        await MarkAsRejectedWithReasonAsync(id,
            $"Rejected by issuance policy before signing. {decision.Summarize()}",
            "queue-consumer", cancellationToken);
        return decision;
    }

    public async Task<CertificateRequest?> MarkAsPendingRevocationAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);

        if (existing is null || existing.Status != CertificateRequestStatus.Issued)
            return null;

        existing.Status = CertificateRequestStatus.PendingRevocation;
        existing.RevocationReason = reason;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("RevocationQueued", performedBy, (Guid)id, existing.CommonName,
            string.IsNullOrWhiteSpace(reason) ? null : $"Reason: {reason}",
            cancellationToken);

        // Stops a revoked root or CA from signing now, not when the consumer gets to the row.
        if (issuerRevocation is not null)
            await issuerRevocation.OnCertificateRevokedAsync(existing, performedBy, cancellationToken);

        return existing;
    }

    public async Task<CertificateRequest?> DequeueNextPendingRevocationAsync(CancellationToken cancellationToken = default)
    {
        // AsNoTracking for the same reason as DequeueNextApprovedAsync: the claim below is an
        // ExecuteUpdateAsync that the change tracker never sees.
        var next = await dbContext.CertificateRequests
            .AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.PendingRevocation)
            .OrderBy(r => r.UpdatedAtUtc)
            .FirstOrDefaultAsync(cancellationToken);

        if (next is null) return null;

        var now = _clock.GetUtcNow().UtcDateTime;
        var rowsAffected = await dbContext.CertificateRequests
            .Where(r => r.Id == next.Id && r.Status == CertificateRequestStatus.PendingRevocation)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, CertificateRequestStatus.Revoked)
                .SetProperty(r => r.RevokedAtUtc, now)
                .SetProperty(r => r.UpdatedAtUtc, now),
                cancellationToken);

        if (rowsAffected == 0) return null; // claimed by another worker

        var claimed = await RefreshTrackedAsync(next.Id, cancellationToken);
        if (claimed is not null) next = claimed;

        // Detached, so this only shapes the returned value.
        next.Status = CertificateRequestStatus.Revoked;
        next.RevokedAtUtc = now;

        await auditLog.LogAsync("Revoked", "queue-consumer", (Guid)next.Id, next.CommonName,
            string.IsNullOrWhiteSpace(next.RevocationReason) ? null : $"Reason: {next.RevocationReason}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Revoked, next, "queue-consumer"), cancellationToken);

        // Idempotent repeat of the queue-time step, so a failure there cannot leave a revoked root signing.
        if (issuerRevocation is not null)
            await issuerRevocation.OnCertificateRevokedAsync(next, "queue-consumer", cancellationToken);

        return next;
    }

    public async Task<CertificateRequest?> MarkAsRevokedAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);

        if (existing is null || existing.Status != CertificateRequestStatus.Issued)
            return null;

        var now = _clock.GetUtcNow().UtcDateTime;
        existing.Status = CertificateRequestStatus.Revoked;
        existing.RevokedAtUtc = now;
        existing.RevocationReason = reason;
        existing.UpdatedAtUtc = now;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("Revoked", performedBy, (Guid)id, existing.CommonName,
            string.IsNullOrWhiteSpace(reason) ? null : $"Reason: {reason}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Revoked, existing, performedBy), cancellationToken);

        if (issuerRevocation is not null)
            await issuerRevocation.OnCertificateRevokedAsync(existing, performedBy, cancellationToken);

        return existing;
    }

    /// <summary>
    /// A root renewal keeps the CA's name, organisation and validity but not the one-off instructions of the
    /// request it renews (replace a given issuer, first root after a revocation): the renewal is its own case,
    /// recognised by <c>RenewedFromId</c>.
    /// </summary>
    private static string? RootRenewalProperties(string? propertiesJson)
    {
        if (string.IsNullOrEmpty(propertiesJson)) return propertiesJson;
        var source = JsonSerializer.Deserialize<RootCaProperties>(propertiesJson);
        if (source is null) return propertiesJson;
        return JsonSerializer.Serialize(new RootCaProperties
        {
            OrganizationName = source.OrganizationName,
            OrganizationalUnit = source.OrganizationalUnit,
            Country = source.Country,
            State = source.State,
            Locality = source.Locality,
            ValidityDays = source.ValidityDays
        });
    }

    public Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => RenewAsync(id, performedBy, caller: null, cancellationToken);

    public async Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);

        if (existing is null) return null;

        // RenewAsync inserts its row directly rather than through CreateAsync, so it needs the same check.
        await EnsureCaAvailableForAsync(existing, cancellationToken);

        var settings = await GetSettingsAsync(cancellationToken);
        var effectiveAlgorithm = existing.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        var pqcVerdict = await EvaluatePqcAsync(existing, effectiveAlgorithm, isRenewal: true,
            PolicyEnforcementStage.Create,
            "Submit a new request with a compliant algorithm instead of renewing.", cancellationToken);

        var renewal = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = existing.CommonName,
            RequestedBy = existing.RequestedBy,
            // Carry ownership across the renewal so the original requester keeps key access.
            RequestedBySubject = existing.RequestedBySubject,
            Type = existing.Type,
            PropertiesJson = existing.Type == WellKnownCertificateTypes.RootCa
                ? RootRenewalProperties(existing.PropertiesJson)
                : existing.PropertiesJson,
            KeyAlgorithm = existing.KeyAlgorithm,
            // Carried so a renewal keeps the shorter window its source asked for; it is
            // re-evaluated against the current policy like any other request.
            ValidityDays = existing.ValidityDays,
            Status = CertificateRequestStatus.Pending,
            RenewedFromId = existing.Id,
            // The renewal starts with its own copy (EF refuses one complex-type instance on two rows).
            Metadata = existing.Metadata with { },
            CreatedAtUtc = _clock.GetUtcNow().UtcDateTime,
            UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime
        };

        // Against the *current* published version, not the one the original was issued under.
        var policyDecision = await EnforcePolicyAsync(renewal, settings, PolicyEnforcementStage.Renew,
            (Guid)existing.Id, performedBy, requester: null, caller, cancellationToken);
        RecordPolicyDecision(renewal, policyDecision);

        dbContext.CertificateRequests.Add(renewal);
        await dbContext.SaveChangesAsync(cancellationToken);

        _pqcStage.Record(pqcVerdict, (Guid)renewal.Id, performedBy);
        AttachWarnings(renewal, pqcVerdict, policyDecision);

        await auditLog.LogAsync("Renewed", performedBy, (Guid)renewal.Id, renewal.CommonName,
            $"Renewed from {existing.Id}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Renewed, renewal, performedBy), cancellationToken);

        return renewal;
    }

    /// <summary>
    /// Replaces the metadata set of a request. Allowed in every status. A change is audited with the
    /// fields that differ; a call that changes nothing writes nothing, and the row's UpdatedAtUtc is not
    /// touched because the dequeue loop reads it. The caller has already been authorized.
    /// </summary>
    /// <returns>The row, or null when no request has that id.</returns>
    public async Task<CertificateRequest?> UpdateMetadataAsync(
        CertificateRequestId id, CertificateMetadata metadata, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(r => r.Id == id, cancellationToken);
        if (existing is null) return null;

        var next = metadata.Normalize();
        var changes = existing.Metadata.ChangesTo(next);
        if (changes.Count == 0) return existing;

        existing.Metadata = next;
        await dbContext.SaveChangesAsync(cancellationToken);

        // Quotes are doubled so a value cannot close its own quote and pose as a further change record.
        static string Show(string? value) => value is null ? "(unknown)" : $"'{value.Replace("'", "''")}'";
        await auditLog.LogAsync("CertificateMetadataUpdated", performedBy, (Guid)id, existing.CommonName,
            string.Join("; ", changes.Select(c => $"{c.Field}: {Show(c.Before)} -> {Show(c.After)}")),
            cancellationToken);
        return existing;
    }

    public async Task<IReadOnlyList<CertificateRequest>> GetCertsNeedingAutoRenewalAsync(int daysBeforeExpiry, CancellationToken cancellationToken = default)
    {
        var threshold = _clock.GetUtcNow().UtcDateTime.AddDays(daysBeforeExpiry);
        var now = _clock.GetUtcNow().UtcDateTime;

        var activeRenewalSourceIds = dbContext.CertificateRequests
            .Where(r => r.RenewedFromId.HasValue &&
                        r.Status != CertificateRequestStatus.Rejected &&
                        r.Status != CertificateRequestStatus.Revoked)
            .Select(r => r.RenewedFromId!.Value);

        // Renewing a CA is a human act (certificates.ca plus an independent approver), never a timer.
        var caTypeKeys = (await dbContext.CertificateTemplates.AsNoTracking()
                .Select(t => new { t.TypeKey, t.KeyUsagesJson }).ToListAsync(cancellationToken))
            .Where(t => CaCapableTemplate.IsCaCapable(t.KeyUsagesJson))
            .Select(t => t.TypeKey)
            .ToList();

        return await dbContext.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Issued &&
                        r.ValidTo.HasValue &&
                        r.ValidTo.Value > now &&
                        r.ValidTo.Value <= threshold &&
                        r.CsrPem == null &&
                        !caTypeKeys.Contains(r.Type!) &&
                        !activeRenewalSourceIds.Contains(r.Id))
            .ToListAsync(cancellationToken);
    }

    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, CancellationToken cancellationToken = default)
        => UpdateAsync(id, request, performedBy, requester: null, caller: null, cancellationToken);

    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, RequesterRoles? requester, CancellationToken cancellationToken = default)
        => UpdateAsync(id, request, performedBy, requester, caller: null, cancellationToken);

    public async Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, CertificateRequest request, string performedBy, RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        var existingRequest = await dbContext.CertificateRequests
            .SingleOrDefaultAsync(certificateRequest => certificateRequest.Id == id, cancellationToken);

        if (existingRequest is null)
            return null;

        var settings = await GetSettingsAsync(cancellationToken);
        var effectiveAlgorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        var pqcVerdict = await EvaluatePqcAsync(request, effectiveAlgorithm,
            isRenewal: existingRequest.RenewedFromId is not null, PolicyEnforcementStage.Update, renewalHint: null, cancellationToken);

        // A PUT can change Type, and with it the governing template and policy.
        var policyDecision = await EnforcePolicyAsync(request, settings, PolicyEnforcementStage.Update,
            (Guid)id, performedBy, requester, caller, cancellationToken);

        // Validate state transition if status is changing
        if (existingRequest.Status != request.Status)
            ValidateTransition(existingRequest.Status, request.Status);

        existingRequest.CommonName = request.CommonName;
        // RequestedBy and RequestedBySubject are deliberately not updated: an update must not
        // reassign a request to another identity, which would also transfer private-key access.
        existingRequest.Type = request.Type;
        existingRequest.PropertiesJson = request.PropertiesJson;
        existingRequest.Status = request.Status;
        existingRequest.KeyAlgorithm = request.KeyAlgorithm;
        existingRequest.ValidityDays = request.ValidityDays;
        RecordPolicyDecision(existingRequest, policyDecision);
        existingRequest.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;

        await dbContext.SaveChangesAsync(cancellationToken);

        _pqcStage.Record(pqcVerdict, (Guid)id, performedBy);
        AttachWarnings(existingRequest, pqcVerdict, policyDecision);

        await auditLog.LogAsync("Updated", performedBy, (Guid)id, existingRequest.CommonName,
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Updated, existingRequest, performedBy), cancellationToken);

        return existingRequest;
    }

    /// <summary>
    /// Evaluates <paramref name="candidate"/> against its template's published policy. A violation
    /// is audited and thrown before the caller saves anything, so no row changes.
    /// </summary>
    private async Task<PolicyDecision> EnforcePolicyAsync(
        CertificateRequest candidate,
        CaSettings settings,
        PolicyEnforcementStage stage,
        Guid? resourceId,
        string performedBy,
        RequesterRoles? requester,
        CallerContext? caller,
        CancellationToken cancellationToken)
    {
        var decision = await issuancePolicy.EvaluateAsync(candidate, settings, requester, caller, cancellationToken);
        if (decision.Allowed)
            return decision;

        var action = stage == PolicyEnforcementStage.Approval ? "ApprovalBlockedByPolicy" : "PolicyRejected";
        await auditLog.LogAsync(action, performedBy, resourceId, candidate.CommonName,
            $"Stage: {stage}. {decision.Summarize()}", cancellationToken);
        throw new IssuancePolicyViolationException(decision, stage);
    }

    /// <summary>What the requester-role rule decided at submission, or null when it did not apply.</summary>
    private static string? RequesterRoleAuditDetail(PolicyDecision decision) =>
        decision.RequesterIsAdmin
            ? "Requester is admin; requester-role rule bypassed."
            : decision.MatchedRequesterRole is { } role
                ? $"Requester role '{role}' admitted by policy '{decision.PolicyName}' v{decision.VersionNumber}."
                : null;

    /// <summary>Records the version that allowed the request; clears it when no policy governs the request.</summary>
    private void RecordPolicyDecision(CertificateRequest row, PolicyDecision decision)
    {
        row.PolicyVersionId = decision.PolicyVersionId;
        row.PolicyEvaluatedAtUtc = decision.PolicyVersionId is null ? null : _clock.GetUtcNow().UtcDateTime;
    }

    // Allowed state machine transitions. Processing is owned by the queue consumer
    // and cannot be set via the public API; it is excluded from user-visible transitions.
    private static readonly Dictionary<CertificateRequestStatus, IReadOnlySet<CertificateRequestStatus>> AllowedTransitions =
        new()
        {
            [CertificateRequestStatus.Pending]    = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Approved, CertificateRequestStatus.Rejected },
            [CertificateRequestStatus.Approved]   = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Processing },
            [CertificateRequestStatus.Processing] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Issued, CertificateRequestStatus.Rejected },
            // Revocation is asynchronous: the API writes PendingRevocation and the consumer finalizes
            // Revoked. Issued -> Revoked stays allowed for MarkAsRevokedAsync, which finalizes in one
            // step. Both revocation states are terminal-ward only — nothing walks back to Issued.
            [CertificateRequestStatus.Issued]     = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.PendingRevocation, CertificateRequestStatus.Revoked },
            [CertificateRequestStatus.PendingRevocation] = new HashSet<CertificateRequestStatus> { CertificateRequestStatus.Revoked },
            [CertificateRequestStatus.Rejected]   = new HashSet<CertificateRequestStatus>(),
            [CertificateRequestStatus.Revoked]    = new HashSet<CertificateRequestStatus>()
        };

    private static void ValidateTransition(CertificateRequestStatus current, CertificateRequestStatus target)
    {
        if (!AllowedTransitions.TryGetValue(current, out var allowed) || !allowed.Contains(target))
            throw new InvalidStateTransitionException(current, target);
    }

    public async Task<bool> DeleteAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
    {
        var existingRequest = await dbContext.CertificateRequests
            .AsNoTracking()
            .SingleOrDefaultAsync(certificateRequest => certificateRequest.Id == id, cancellationToken);

        if (existingRequest is null)
        {
            return false;
        }

        // Keep certificate and revocation evidence once issuance is approved. The status predicate
        // is part of the DELETE itself, so an approval racing this operation wins rather than
        // letting a stale read remove a now-protected record.
        var deleted = await dbContext.CertificateRequests
            .Where(certificateRequest => certificateRequest.Id == id &&
                                         (certificateRequest.Status == CertificateRequestStatus.Pending ||
                                          certificateRequest.Status == CertificateRequestStatus.Rejected))
            .ExecuteDeleteAsync(cancellationToken);

        if (deleted == 0)
        {
            var currentStatus = await dbContext.CertificateRequests
                .AsNoTracking()
                .Where(certificateRequest => certificateRequest.Id == id)
                .Select(certificateRequest => (CertificateRequestStatus?)certificateRequest.Status)
                .SingleOrDefaultAsync(cancellationToken);

            if (currentStatus is null)
                return false;

            throw new CertificateRequestDeletionConflictException(currentStatus.Value);
        }

        // Notes belong to the request and go with it (no foreign key: SQLite cascades only with foreign keys on).
        await dbContext.CertificateNotes.Where(n => n.RequestId == id).ExecuteDeleteAsync(cancellationToken);

        await auditLog.LogAsync("Deleted", performedBy, (Guid)id, existingRequest.CommonName,
            cancellationToken: cancellationToken);
        // The row is gone; the instance in hand is what describes what was deleted.
        await webhookService.EnqueueEventAsync(
            RequestEvent(WellKnownWebhookEvents.Deleted, existingRequest, performedBy), cancellationToken);

        return true;
    }

    public async Task<CertificateDashboardSummary> GetDashboardSummaryAsync(CancellationToken cancellationToken = default)
    {
        var settings = await GetSettingsAsync(cancellationToken);
        var now = _clock.GetUtcNow().UtcDateTime;
        var expiringSoonThreshold = now.AddDays(settings.ExpiringSoonDays);

        // Aggregate in the database: one GroupBy over a constant key becomes a single row of
        // SUM(CASE WHEN ...) columns, so the cost no longer grows with the number of issued
        // certificates. Count(predicate) inside the grouping projection is what EF translates
        // into those conditional sums — do not pull the rows back and count in memory.
        // "IssuedCount includes Revoked" is a deliberate dashboard semantic: a revoked certificate was issued.
        var counts = await dbContext.CertificateRequests
            .GroupBy(_ => 1)
            .Select(g => new
            {
                TotalCount        = g.Count(),
                PendingCount      = g.Count(r => r.Status == CertificateRequestStatus.Pending),
                ApprovedCount     = g.Count(r => r.Status == CertificateRequestStatus.Approved),
                RejectedCount     = g.Count(r => r.Status == CertificateRequestStatus.Rejected),
                IssuedCount       = g.Count(r => r.Status == CertificateRequestStatus.Issued || r.Status == CertificateRequestStatus.Revoked),
                ValidCount        = g.Count(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo > expiringSoonThreshold),
                ExpiringSoonCount = g.Count(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo > now && r.ValidTo <= expiringSoonThreshold),
                ExpiredCount      = g.Count(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo <= now),
                RevokedCount      = g.Count(r => r.Status == CertificateRequestStatus.Revoked)
            })
            .FirstOrDefaultAsync(cancellationToken);

        var recentRequests = await WithoutPrivateKeys(
                dbContext.CertificateRequests.OrderByDescending(r => r.UpdatedAtUtc))
            .Take(10)
            .ToListAsync(cancellationToken);

        // An empty table produces no groups, so the aggregate query yields no row at all.
        return new CertificateDashboardSummary
        {
            TotalCount        = counts?.TotalCount ?? 0,
            PendingCount      = counts?.PendingCount ?? 0,
            ApprovedCount     = counts?.ApprovedCount ?? 0,
            RejectedCount     = counts?.RejectedCount ?? 0,
            IssuedCount       = counts?.IssuedCount ?? 0,
            ValidCount        = counts?.ValidCount ?? 0,
            ExpiringSoonCount = counts?.ExpiringSoonCount ?? 0,
            ExpiredCount      = counts?.ExpiredCount ?? 0,
            RevokedCount      = counts?.RevokedCount ?? 0,
            RecentRequests    = recentRequests
        };
    }

    public async Task<CaSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        var settings = await dbContext.Settings.SingleOrDefaultAsync(s => s.Id == 1, cancellationToken);
        if (settings != null)
            return settings;

        settings = new CaSettings { Id = 1 };
        dbContext.Settings.Add(settings);
        await dbContext.SaveChangesAsync(cancellationToken);
        return settings;
    }

    public async Task<CaSettings> SetPqcStageAsync(PqcStage stage, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await GetSettingsAsync(cancellationToken); // creates the singleton row when missing
        var previous = existing.PqcStage;
        if (previous == stage) return existing;

        existing.PqcStage = stage;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("PqcStageChanged", performedBy,
            detail: $"PQC stage: {previous} -> {stage}", cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.PqcStageChanged, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["previousStage"] = previous.ToString(),
                ["stage"] = stage.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CaSettings> SetIssuerStrengthAsync(IssuerStrengthMode mode, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await GetSettingsAsync(cancellationToken);
        var previous = existing.IssuerStrengthMode;
        if (previous == mode) return existing;

        existing.IssuerStrengthMode = mode;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(WellKnownWebhookEvents.IssuerStrengthChanged, performedBy,
            detail: $"Issuer strength: {previous} -> {mode}", cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuerStrengthChanged, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["previousMode"] = previous.ToString(),
                ["mode"] = mode.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CaSettings> SetRevokedIssuerModeAsync(RevokedIssuerMode mode, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await GetSettingsAsync(cancellationToken);
        var previous = existing.RevokedIssuerMode;
        if (previous == mode) return existing;

        existing.RevokedIssuerMode = mode;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(WellKnownWebhookEvents.RevokedIssuerModeChanged, performedBy,
            detail: $"Revoked issuer: {previous} -> {mode}", cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.RevokedIssuerModeChanged, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["previousMode"] = previous.ToString(),
                ["mode"] = mode.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CaSettings> SetCaApprovalRuleAsync(bool requireIndependent, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await GetSettingsAsync(cancellationToken);
        var previous = existing.RequireIndependentCaApproval;
        if (previous == requireIndependent) return existing;

        existing.RequireIndependentCaApproval = requireIndependent;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(WellKnownWebhookEvents.CaApprovalRuleChanged, performedBy,
            detail: $"CA approval: {CaApprovalRule.ModeName(previous)} -> {CaApprovalRule.ModeName(requireIndependent)}",
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.CaApprovalRuleChanged, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["previousApprovalMode"] = CaApprovalRule.ModeName(previous),
                ["approvalMode"] = CaApprovalRule.ModeName(requireIndependent)
            }), cancellationToken);
        return existing;
    }

    public async Task<CaSettings> SetTwoPersonApprovalAsync(bool enabled, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await GetSettingsAsync(cancellationToken);
        var previous = existing.RequireTwoPersonApproval;
        if (previous == enabled) return existing;

        existing.RequireTwoPersonApproval = enabled;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(WellKnownWebhookEvents.TwoPersonApprovalChanged, performedBy,
            detail: $"Two-person approval: {(previous ? "on" : "off")} -> {(enabled ? "on" : "off")}",
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TwoPersonApprovalChanged, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["twoPersonApproval"] = enabled ? "on" : "off"
            }), cancellationToken);
        return existing;
    }

    public async Task<CaSettings> SetupOrUpdateSettingsAsync(CaSettings settings, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.Settings.SingleOrDefaultAsync(s => s.Id == 1, cancellationToken);
        if (existing == null)
        {
            settings.Id = 1;
            settings.RequireIndependentCaApproval = true;
            settings.RequireTwoPersonApproval = false; // owned by PUT /v1/settings/two-person-approval (admin only)
            settings.IssuerStrengthMode = IssuerStrengthMode.Warn; // owned by PUT /v1/settings/issuer-strength (admin only)
            settings.RevokedIssuerMode = RevokedIssuerMode.HardStop; // owned by PUT /v1/settings/revoked-issuer (admin only)
            dbContext.Settings.Add(settings);
        }
        else
        {
            // Copy every mapped property rather than listing them by hand. The previous hand-copy had
            // silently omitted AcmeAutoApprove, so the Settings toggle bound to it was a permanent
            // no-op; any field added later would have inherited the same bug.
            settings.Id = existing.Id;
            // CrlNumber and the delta-CRL base fields are owned by the CRL publisher, not the
            // settings form. Carrying the stored values across the copy stops a save from resetting
            // the counter or discarding the delta CRL's reference point.
            settings.CrlNumber = existing.CrlNumber;
            settings.BaseCrlNumber = existing.BaseCrlNumber;
            settings.BaseCrlThisUpdateUtc = existing.BaseCrlThisUpdateUtc;
            // The stage is owned by PUT /v1/settings/pqc-stage (admin only). Carrying the stored value
            // across the copy means a general save can neither weaken nor tighten it, whatever the client posted.
            settings.PqcStage = existing.PqcStage;
            settings.RequireIndependentCaApproval = existing.RequireIndependentCaApproval; // owned by PUT /v1/settings/ca-approval (admin only)
            settings.RequireTwoPersonApproval = existing.RequireTwoPersonApproval; // owned by PUT /v1/settings/two-person-approval (admin only)
            settings.IssuerStrengthMode = existing.IssuerStrengthMode; // owned by PUT /v1/settings/issuer-strength (admin only)
            settings.RevokedIssuerMode = existing.RevokedIssuerMode; // owned by PUT /v1/settings/revoked-issuer (admin only)
            dbContext.Entry(existing).CurrentValues.SetValues(settings);
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("SettingsUpdated", performedBy,
            detail: $"Organization: {settings.OrganizationName}",
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.SettingsUpdated, PerformedBy: performedBy), cancellationToken);

        return existing ?? settings;
    }

    public Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, CancellationToken cancellationToken = default)
        => RevocationStatusesAsync(dbContext.CertificateRequests, serialNumbers, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, Issuers.IssuerScope scope, CancellationToken cancellationToken = default)
        => RevocationStatusesAsync(InScope(scope), serialNumbers, cancellationToken);

    private static async Task<IReadOnlyDictionary<string, OcspCertificateStatus>> RevocationStatusesAsync(
        IQueryable<CertificateRequest> source, IReadOnlyCollection<string> serialNumbers, CancellationToken cancellationToken)
    {
        if (serialNumbers.Count == 0)
            return new Dictionary<string, OcspCertificateStatus>();

        var rows = await source
            .AsNoTracking()
            .Where(r => (r.SerialNumber != null && serialNumbers.Contains(r.SerialNumber))
                || (r.PqcSerialNumber != null && serialNumbers.Contains(r.PqcSerialNumber)))
            .Select(r => new { r.SerialNumber, r.PqcSerialNumber, r.Status, r.RevokedAtUtc, r.RevocationReason })
            .ToListAsync(cancellationToken);

        var result = new Dictionary<string, OcspCertificateStatus>(rows.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            // Only a finalised revocation counts. PendingRevocation is still absent from the CRL, and
            // a responder that called it revoked would contradict the CRL for as long as the queue
            // takes to catch up.
            var status = row.Status == CertificateRequestStatus.Revoked
                ? new OcspCertificateStatus(OcspCertificateState.Revoked, row.RevokedAtUtc, row.RevocationReason)
                : OcspCertificateStatus.Good;

            // Both certificates of a pair share the request's status: they are issued and revoked together.
            if (row.SerialNumber is not null) result[row.SerialNumber] = status;
            if (row.PqcSerialNumber is not null) result[row.PqcSerialNumber] = status;
        }

        return result;
    }

    public async Task<long> ClaimNextCrlNumberAsync(CancellationToken cancellationToken = default)
    {
        // Ensure the singleton row exists before incrementing it.
        await GetSettingsAsync(cancellationToken);

        // ExecuteUpdateAsync issues a single UPDATE ... SET CrlNumber = CrlNumber + 1, so the
        // increment happens in the database rather than read-modify-write in memory. Two instances
        // publishing simultaneously therefore claim distinct numbers.
        await dbContext.Settings
            .Where(s => s.Id == 1)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.CrlNumber, x => x.CrlNumber + 1), cancellationToken);

        // The tracked entity still holds the pre-increment value after ExecuteUpdateAsync.
        return await dbContext.Settings
            .Where(s => s.Id == 1)
            .AsNoTracking()
            .Select(s => s.CrlNumber)
            .SingleAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task RecordBaseCrlAsync(long crlNumber, DateTime thisUpdateUtc, CancellationToken cancellationToken = default)
    {
        await dbContext.Settings
            .Where(s => s.Id == 1)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.BaseCrlNumber, crlNumber)
                .SetProperty(x => x.BaseCrlThisUpdateUtc, thisUpdateUtc), cancellationToken);

        // ExecuteUpdateAsync writes past the change tracker, so a Settings row this context already
        // tracks (e.g. from an earlier GetSettingsAsync in the same scope) keeps its pre-update
        // snapshot until reloaded — the same hazard ClaimNextCrlNumberAsync's callers avoid by
        // re-querying AsNoTracking. Here the tracked instance itself is what callers hold onto next,
        // so refresh it in place instead.
        var tracked = dbContext.Settings.Local.FirstOrDefault(s => s.Id == 1);
        if (tracked is not null)
            await dbContext.Entry(tracked).ReloadAsync(cancellationToken);
    }

    public async Task<Guid?> GetPendingRootCaRequestIdAsync(CancellationToken cancellationToken = default)
    {
        return await dbContext.CertificateRequests
            .Where(r => r.Type == WellKnownCertificateTypes.RootCa &&
                   (r.Status == CertificateRequestStatus.Pending ||
                    r.Status == CertificateRequestStatus.Approved ||
                    r.Status == CertificateRequestStatus.Processing))
            .OrderBy(r => r.CreatedAtUtc)
            .Select(r => (Guid?)((Guid)r.Id))
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <summary>
    /// A certificate-request family event describing <paramref name="request"/>. Every field here is
    /// in WebhookEventFields' CertificateRequest allowlist; never add key material.
    /// </summary>
    private static WebhookEvent RequestEvent(string eventType, CertificateRequest request, string? performedBy) =>
        new(eventType,
            (Guid)request.Id,
            request.CommonName,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["commonName"] = request.CommonName,
                ["status"] = request.Status.ToString(),
                ["certificateType"] = request.Type,
                ["keyAlgorithm"] = request.KeyAlgorithm?.ToCanonicalString(),
                ["serialNumber"] = request.SerialNumber,
                ["validTo"] = request.ValidTo?.ToString("O"),
                ["failureReason"] = request.FailureReason,
                ["requestedBy"] = request.RequestedBy
                ,
                ["ownerTeam"] = request.Metadata.OwnerTeam,
                ["targetSystem"] = request.Metadata.TargetSystem,
                ["ticketReference"] = request.Metadata.TicketReference,
                ["purpose"] = request.Metadata.Purpose
            });
}
