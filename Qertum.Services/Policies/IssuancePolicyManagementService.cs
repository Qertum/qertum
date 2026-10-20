using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Policies;

public interface IIssuancePolicyManagementService
{
    Task<IReadOnlyList<IssuancePolicySummaryResponse>> ListAsync(CancellationToken cancellationToken = default);

    Task<IssuancePolicyResponse?> GetAsync(IssuancePolicyId id, CancellationToken cancellationToken = default);

    /// <summary>All versions, newest first; null when the policy does not exist.</summary>
    Task<IReadOnlyList<IssuancePolicyVersionResponse>?> GetVersionsAsync(IssuancePolicyId id, CancellationToken cancellationToken = default);

    /// <summary>Creates the policy with an empty draft v1 and nothing published.</summary>
    Task<IssuancePolicyResponse> CreateAsync(SaveIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default);

    Task<IssuancePolicyResponse?> UpdateAsync(IssuancePolicyId id, SaveIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>Replaces every rule on the draft, opening a new draft when none exists.</summary>
    Task<IssuancePolicyResponse?> SaveDraftAsync(IssuancePolicyId id, SaveIssuancePolicyDraftRequest request, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>False when the policy does not exist; conflict when it has no draft.</summary>
    Task<bool> DiscardDraftAsync(IssuancePolicyId id, string performedBy, CancellationToken cancellationToken = default);

    Task<IssuancePolicyResponse?> PublishAsync(IssuancePolicyId id, PublishIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default);

    Task<IssuancePolicyResponse?> SetArchivedAsync(IssuancePolicyId id, bool archived, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>False when the policy does not exist; conflict when a template links to it or a request was allowed under it.</summary>
    Task<bool> DeleteAsync(IssuancePolicyId id, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether a template with default validity <paramref name="templateValidityDays"/> may be governed
    /// by <paramref name="policyId"/>. Null when allowed (always, for a null policy); a message when the
    /// policy is missing, archived, or unpublished. Throws <see cref="IssuancePolicyInvariantException"/>
    /// when the template's default validity exceeds the published maximum.
    /// </summary>
    Task<string?> ValidateTemplateLinkAsync(IssuancePolicyId? policyId, string typeKey, int? templateValidityDays, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether <paramref name="candidate"/> may be saved. Null when allowed; a message when a
    /// protocol template key names no template. Throws <see cref="IssuancePolicyInvariantException"/>
    /// when the new global validity would push a linked template's default above its policy maximum.
    /// </summary>
    Task<string?> ValidateSettingsAsync(CaSettings candidate, CancellationToken cancellationToken = default);
}

internal sealed class IssuancePolicyManagementService(
    CertificateRequestDbContext db,
    IAuditLogService auditLog,
    IWebhookService webhookService,
    TimeProvider? timeProvider = null) : IIssuancePolicyManagementService
{
    // Time is read through TimeProvider so expiry and scheduling can be tested with a fake clock;
    // optional so code that constructs this directly keeps compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<IssuancePolicySummaryResponse>> ListAsync(CancellationToken cancellationToken = default)
    {
        var policies = await db.IssuancePolicies
            .AsNoTracking()
            .Include(p => p.Versions)
            .OrderBy(p => p.Name)
            .ToListAsync(cancellationToken);

        var links = await db.CertificateTemplates
            .AsNoTracking()
            .Where(t => t.IssuancePolicyId != null)
            .Select(t => t.IssuancePolicyId)
            .ToListAsync(cancellationToken);

        return policies.Select(p => new IssuancePolicySummaryResponse
        {
            Id = p.Id,
            Name = p.Name,
            Description = p.Description,
            IsArchived = p.IsArchived,
            PublishedVersionNumber = p.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Published)?.VersionNumber,
            HasDraft = p.Versions.Any(v => v.Status == IssuancePolicyVersionStatus.Draft),
            LinkedTemplateCount = links.Count(l => l == p.Id)
        }).ToList();
    }

    public async Task<IssuancePolicyResponse?> GetAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var policy = await db.IssuancePolicies
            .AsNoTracking()
            .Include(p => p.Versions)
            .FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        return policy is null ? null : await ToResponseAsync(policy, cancellationToken);
    }

    public async Task<IReadOnlyList<IssuancePolicyVersionResponse>?> GetVersionsAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        if (!await db.IssuancePolicies.AnyAsync(p => p.Id == id, cancellationToken))
            return null;

        var versions = await db.IssuancePolicyVersions
            .AsNoTracking()
            .Where(v => v.PolicyId == id)
            .OrderByDescending(v => v.VersionNumber)
            .ToListAsync(cancellationToken);
        return versions.Select(v => ToVersionResponse(v)!).ToList();
    }

    public async Task<IssuancePolicyResponse> CreateAsync(SaveIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default)
    {
        var name = request.Name.Trim();
        if (await db.IssuancePolicies.AnyAsync(p => p.Name == name, cancellationToken))
            throw new IssuancePolicyConflictException($"An issuance policy named '{name}' already exists.");

        var now = _clock.GetUtcNow().UtcDateTime;
        var policy = new IssuancePolicy
        {
            Name = name,
            Description = request.Description,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
        policy.Versions.Add(new IssuancePolicyVersion
        {
            PolicyId = policy.Id,
            VersionNumber = 1,
            Status = IssuancePolicyVersionStatus.Draft,
            CreatedBy = performedBy,
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        });
        db.IssuancePolicies.Add(policy);
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyCreated", performedBy, (Guid)policy.Id, policy.Name,
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyCreated, (Guid)policy.Id, policy.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = policy.Name
            }), cancellationToken);
        return (await GetAsync(policy.Id, cancellationToken))!;
    }

    public async Task<IssuancePolicyResponse?> UpdateAsync(IssuancePolicyId id, SaveIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default)
    {
        var policy = await db.IssuancePolicies.FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        if (policy is null) return null;

        var name = request.Name.Trim();
        if (await db.IssuancePolicies.AnyAsync(p => p.Name == name && p.Id != id, cancellationToken))
            throw new IssuancePolicyConflictException($"An issuance policy named '{name}' already exists.");

        policy.Name = name;
        policy.Description = request.Description;
        policy.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyUpdated", performedBy, (Guid)id, policy.Name,
            cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyUpdated, (Guid)id, policy.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = policy.Name
            }), cancellationToken);
        return await GetAsync(id, cancellationToken);
    }

    public async Task<IssuancePolicyResponse?> SaveDraftAsync(IssuancePolicyId id, SaveIssuancePolicyDraftRequest request, string performedBy, CancellationToken cancellationToken = default)
    {
        var policy = await LoadTrackedAsync(id, cancellationToken);
        if (policy is null) return null;
        if (policy.IsArchived)
            throw new IssuancePolicyConflictException($"Issuance policy '{policy.Name}' is archived.");

        var now = _clock.GetUtcNow().UtcDateTime;
        var draft = policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Draft);
        if (draft is null)
        {
            draft = new IssuancePolicyVersion
            {
                PolicyId = policy.Id,
                VersionNumber = policy.Versions.Select(v => v.VersionNumber).DefaultIfEmpty(0).Max() + 1,
                Status = IssuancePolicyVersionStatus.Draft,
                CreatedBy = performedBy,
                CreatedAtUtc = now
            };
            db.IssuancePolicyVersions.Add(draft);
        }

        draft.AllowedDnsSuffixesJson = JsonSerializer.Serialize(request.AllowedDnsSuffixes
            .Select(IssuancePolicyEvaluator.NormalizeDns).OfType<string>().Distinct().ToList());
        draft.AllowedIpRangesJson = JsonSerializer.Serialize(request.AllowedIpRanges
            .Select(r => r.Trim()).Where(r => r.Length > 0).Distinct().ToList());
        draft.AllowedKeyAlgorithmsJson = JsonSerializer.Serialize(request.AllowedKeyAlgorithms
            .Select(a => (CertificateKeyAlgorithmExtensions.Parse(a.Trim())
                          ?? throw new ArgumentException($"Unsupported key algorithm '{a}'.")).ToCanonicalString())
            .Distinct().ToList());
        draft.AllowedRequesterRolesJson = JsonSerializer.Serialize(request.AllowedRequesterRoles
            .Select(r => r.Trim()).Where(r => r.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        draft.KeyCustody = request.KeyCustody;
        draft.MaxValidityDays = request.MaxValidityDays;
        draft.UpdatedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyDraftSaved", performedBy, (Guid)id, policy.Name,
            $"Draft v{draft.VersionNumber}", cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyDraftSaved, (Guid)id, policy.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = policy.Name,
                ["versionNumber"] = draft.VersionNumber.ToString(),
                ["versionStatus"] = draft.Status.ToString()
            }), cancellationToken);
        return await GetAsync(id, cancellationToken);
    }

    public async Task<bool> DiscardDraftAsync(IssuancePolicyId id, string performedBy, CancellationToken cancellationToken = default)
    {
        var policy = await LoadTrackedAsync(id, cancellationToken);
        if (policy is null) return false;

        var draft = policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Draft)
                    ?? throw new IssuancePolicyConflictException($"Issuance policy '{policy.Name}' has no draft.");
        db.IssuancePolicyVersions.Remove(draft);
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyDraftDiscarded", performedBy, (Guid)id, policy.Name,
            $"Draft v{draft.VersionNumber}", cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyDraftDiscarded, (Guid)id, policy.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = policy.Name,
                ["versionNumber"] = draft.VersionNumber.ToString(),
                ["versionStatus"] = draft.Status.ToString()
            }), cancellationToken);
        return true;
    }

    public async Task<IssuancePolicyResponse?> PublishAsync(IssuancePolicyId id, PublishIssuancePolicyRequest request, string performedBy, CancellationToken cancellationToken = default)
    {
        var policy = await LoadTrackedAsync(id, cancellationToken);
        if (policy is null) return null;
        if (policy.IsArchived)
            throw new IssuancePolicyConflictException($"Issuance policy '{policy.Name}' is archived.");

        var draft = policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Draft)
                    ?? throw new IssuancePolicyConflictException($"Issuance policy '{policy.Name}' has no draft to publish.");

        // Publishing enforces whatever the draft holds at this moment. Requiring the exact draft the
        // publisher read stops an edit made after their review from being enforced unseen.
        if (draft.Id != request.DraftVersionId || draft.UpdatedAtUtc.Ticks != request.DraftUpdatedAtUtc.Ticks)
            throw new IssuancePolicyConflictException(
                "The draft has changed since it was reviewed. Reload it and publish again.");

        if (draft.MaxValidityDays is int max)
        {
            var settings = await db.Settings.AsNoTracking().SingleOrDefaultAsync(s => s.Id == 1, cancellationToken)
                           ?? new CaSettings();
            var linked = await db.CertificateTemplates
                .AsNoTracking()
                .Where(t => t.IssuancePolicyId == (IssuancePolicyId?)id)
                .ToListAsync(cancellationToken);
            var exceeding = linked
                .Select(t => (t.TypeKey, Days: ValidityDefaults.EffectiveValidityDays(t, settings)))
                .Where(t => t.Days > max)
                .Select(t => $"{t.TypeKey} ({t.Days} days)")
                .ToList();
            if (exceeding.Count > 0)
                throw new IssuancePolicyInvariantException(
                    $"Maximum validity of {max} days is below the default validity of linked templates: {string.Join(", ", exceeding)}.");
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        // Supersede first, in its own statement: the one-published-per-policy index is checked per
        // statement, and EF does not guarantee UPDATE ordering within a single SaveChanges.
        var current = policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Published);
        if (current is not null)
        {
            current.Status = IssuancePolicyVersionStatus.Superseded;
            await db.SaveChangesAsync(cancellationToken);
        }

        draft.Status = IssuancePolicyVersionStatus.Published;
        draft.PublishedBy = performedBy;
        draft.PublishedAtUtc = now;
        policy.UpdatedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyPublished", performedBy, (Guid)id, policy.Name,
            $"Published v{draft.VersionNumber}", cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyPublished, (Guid)id, policy.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = policy.Name,
                ["versionNumber"] = draft.VersionNumber.ToString(),
                ["versionStatus"] = draft.Status.ToString()
            }), cancellationToken);
        return await GetAsync(id, cancellationToken);
    }

    public async Task<IssuancePolicyResponse?> SetArchivedAsync(IssuancePolicyId id, bool archived, string performedBy, CancellationToken cancellationToken = default)
    {
        var policy = await db.IssuancePolicies.FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        if (policy is null) return null;

        if (archived && await IsLinkedAsync(id, cancellationToken))
            throw new IssuancePolicyConflictException(
                $"Issuance policy '{policy.Name}' is linked to a template. Unlink it before archiving.");

        policy.IsArchived = archived;
        policy.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(archived ? "IssuancePolicyArchived" : "IssuancePolicyUnarchived", performedBy,
            (Guid)id, policy.Name, cancellationToken: cancellationToken);
        return await GetAsync(id, cancellationToken);
    }

    public async Task<bool> DeleteAsync(IssuancePolicyId id, string performedBy, CancellationToken cancellationToken = default)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);

        var policy = await LoadTrackedAsync(id, cancellationToken);
        if (policy is null) return false;

        if (await IsLinkedAsync(id, cancellationToken))
            throw new IssuancePolicyConflictException(
                $"Issuance policy '{policy.Name}' is linked to a template. Unlink it before deleting.");

        // Once a request has been allowed under a version, that version is part of the request's
        // record. The restrict FK on PolicyVersionId backstops this check.
        var versionIds = policy.Versions.Select(v => v.Id).ToList();
        if (await db.CertificateRequests.AnyAsync(
                r => r.PolicyVersionId != null && versionIds.Contains(r.PolicyVersionId.Value), cancellationToken))
            throw new IssuancePolicyConflictException(
                $"Certificate requests were allowed under issuance policy '{policy.Name}'. Archive it instead.");

        var name = policy.Name;
        db.IssuancePolicies.Remove(policy);
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        await auditLog.LogAsync("IssuancePolicyDeleted", performedBy, (Guid)id, name,
            $"Versions deleted: {versionIds.Count}", cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyDeleted, (Guid)id, name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["policyName"] = name
            }), cancellationToken);
        return true;
    }

    public async Task<string?> ValidateTemplateLinkAsync(IssuancePolicyId? policyId, string typeKey, int? templateValidityDays, CancellationToken cancellationToken = default)
    {
        if (policyId is not { } id)
            return null;

        var policy = await db.IssuancePolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, cancellationToken);
        if (policy is null)
            return $"Issuance policy {id} does not exist.";
        if (policy.IsArchived)
            return $"Issuance policy '{policy.Name}' is archived.";

        var published = await db.IssuancePolicyVersions.AsNoTracking()
            .FirstOrDefaultAsync(v => v.PolicyId == id && v.Status == IssuancePolicyVersionStatus.Published, cancellationToken);
        if (published is null)
            return $"Issuance policy '{policy.Name}' has no published version.";

        if (published.MaxValidityDays is int max)
        {
            var settings = await db.Settings.AsNoTracking().SingleOrDefaultAsync(s => s.Id == 1, cancellationToken)
                           ?? new CaSettings();
            var days = ValidityDefaults.EffectiveValidityDays(new CertificateTemplate { ValidityDays = templateValidityDays }, settings);
            if (days > max)
                throw new IssuancePolicyInvariantException(
                    $"Template '{typeKey}' defaults to {days} days of validity, above the maximum of {max} days in issuance policy '{policy.Name}'.");
        }

        return null;
    }

    public async Task<string?> ValidateSettingsAsync(CaSettings candidate, CancellationToken cancellationToken = default)
    {
        foreach (var (protocol, typeKey) in new[] { ("ACME", candidate.AcmeTemplateTypeKey), ("EST", candidate.EstTemplateTypeKey) })
        {
            if (string.IsNullOrWhiteSpace(typeKey))
                return $"The {protocol} issuance template must be set.";
            var template = await db.CertificateTemplates.AsNoTracking()
                .FirstOrDefaultAsync(t => t.TypeKey == typeKey, cancellationToken);
            if (template is null)
                return $"The {protocol} issuance template '{typeKey}' does not exist.";
            if (CaCapableTemplate.IsCaCapable(template))
                return $"The {protocol} issuance template '{typeKey}' issues a CA certificate (KeyCertSign); " +
                       $"{protocol} requests are never approved by a person, so it cannot be used.";
        }

        // A template with no validity of its own inherits the global default, so raising that default
        // can push it past the maximum of the policy governing it — which would reject every request
        // filed under that template.
        var offenders = await db.CertificateTemplates.AsNoTracking()
            .Where(t => t.IssuancePolicyId != null && t.ValidityDays == null)
            .Join(db.IssuancePolicyVersions.AsNoTracking()
                    .Where(v => v.Status == IssuancePolicyVersionStatus.Published && v.MaxValidityDays != null),
                t => t.IssuancePolicyId!.Value, v => v.PolicyId,
                (t, v) => new { t.TypeKey, Max = v.MaxValidityDays!.Value })
            .Where(x => candidate.CertificateValidityDays > x.Max)
            .ToListAsync(cancellationToken);
        if (offenders.Count > 0)
            throw new IssuancePolicyInvariantException(
                $"A default validity of {candidate.CertificateValidityDays} days exceeds the issuance policy maximum for " +
                string.Join(", ", offenders.Select(o => $"template '{o.TypeKey}' ({o.Max} days)")) + ".");

        return null;
    }

    private Task<IssuancePolicy?> LoadTrackedAsync(IssuancePolicyId id, CancellationToken cancellationToken) =>
        db.IssuancePolicies.Include(p => p.Versions).FirstOrDefaultAsync(p => p.Id == id, cancellationToken);

    private Task<bool> IsLinkedAsync(IssuancePolicyId id, CancellationToken cancellationToken) =>
        db.CertificateTemplates.AnyAsync(t => t.IssuancePolicyId == (IssuancePolicyId?)id, cancellationToken);

    private async Task<IssuancePolicyResponse> ToResponseAsync(IssuancePolicy policy, CancellationToken cancellationToken)
    {
        var policyId = (IssuancePolicyId?)policy.Id;
        var linked = await db.CertificateTemplates
            .AsNoTracking()
            .Where(t => t.IssuancePolicyId == policyId)
            .OrderBy(t => t.TypeKey)
            .Select(t => t.TypeKey)
            .ToListAsync(cancellationToken);

        return new IssuancePolicyResponse
        {
            Id = policy.Id,
            Name = policy.Name,
            Description = policy.Description,
            IsArchived = policy.IsArchived,
            CreatedAtUtc = policy.CreatedAtUtc,
            UpdatedAtUtc = policy.UpdatedAtUtc,
            Published = ToVersionResponse(policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Published)),
            Draft = ToVersionResponse(policy.Versions.FirstOrDefault(v => v.Status == IssuancePolicyVersionStatus.Draft)),
            LinkedTemplateTypeKeys = linked
        };
    }

    internal static IssuancePolicyVersionResponse? ToVersionResponse(IssuancePolicyVersion? version) =>
        version is null
            ? null
            : new IssuancePolicyVersionResponse
            {
                Id = version.Id,
                VersionNumber = version.VersionNumber,
                Status = version.Status,
                AllowedDnsSuffixes = IssuancePolicyEvaluator.ReadList(version.AllowedDnsSuffixesJson),
                AllowedIpRanges = IssuancePolicyEvaluator.ReadList(version.AllowedIpRangesJson),
                AllowedKeyAlgorithms = IssuancePolicyEvaluator.ReadList(version.AllowedKeyAlgorithmsJson),
                AllowedRequesterRoles = IssuancePolicyEvaluator.ReadList(version.AllowedRequesterRolesJson),
                KeyCustody = version.KeyCustody,
                MaxValidityDays = version.MaxValidityDays,
                CreatedBy = version.CreatedBy,
                CreatedAtUtc = version.CreatedAtUtc,
                UpdatedAtUtc = version.UpdatedAtUtc,
                PublishedBy = version.PublishedBy,
                PublishedAtUtc = version.PublishedAtUtc
            };
}
