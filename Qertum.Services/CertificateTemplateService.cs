using Microsoft.EntityFrameworkCore;

namespace Qertum.Services;

internal sealed class CertificateTemplateService(
    CertificateRequestDbContext db,
    IAuditLogService auditLog,
    IWebhookService webhookService,
    TimeProvider? timeProvider = null) : ICertificateTemplateService
{
    // Time is read through TimeProvider so expiry and scheduling can be tested with a fake clock;
    // optional so code that constructs this directly keeps compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<IReadOnlyList<CertificateTemplate>> GetAllAsync(CancellationToken cancellationToken = default)
        => await db.CertificateTemplates
            .OrderByDescending(t => t.IsBuiltIn)
            .ThenBy(t => t.Name)
            .ToListAsync(cancellationToken);

    public Task<CertificateTemplate?> GetByIdAsync(CertificateTemplateId id, CancellationToken cancellationToken = default)
        => db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);

    public Task<CertificateTemplate?> GetByTypeKeyAsync(string typeKey, CancellationToken cancellationToken = default)
        => db.CertificateTemplates.FirstOrDefaultAsync(t => t.TypeKey == typeKey, cancellationToken);

    public async Task<CertificateTemplate> CreateAsync(CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default)
    {
        template.Id = Guid.NewGuid();
        template.IsBuiltIn = false;
        template.CreatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        template.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        db.CertificateTemplates.Add(template);
        await db.SaveChangesAsync(cancellationToken);
        await auditLog.LogAsync("TemplateCreated", performedBy, (Guid)template.Id, template.Name, cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplateCreated, (Guid)template.Id, template.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = template.Name,
                ["typeKey"] = template.TypeKey,
                ["issuancePolicyId"] = template.IssuancePolicyId?.ToString(),
                ["issuerId"] = template.IssuerId?.ToString()
            }), cancellationToken);
        return template;
    }

    public async Task<CertificateTemplate?> UpdateAsync(CertificateTemplateId id, CertificateTemplate template, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (existing is null) return null;

        existing.Name = template.Name;
        existing.Description = template.Description;
        existing.KeyUsagesJson = template.KeyUsagesJson;
        existing.ExtendedKeyUsagesJson = template.ExtendedKeyUsagesJson;
        existing.SanTypesJson = template.SanTypesJson;
        existing.CustomExtensionsJson = template.CustomExtensionsJson;
        existing.ValidityDays = template.ValidityDays;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;

        if (!existing.IsBuiltIn)
            existing.TypeKey = template.TypeKey;

        await db.SaveChangesAsync(cancellationToken);
        await auditLog.LogAsync("TemplateUpdated", performedBy, (Guid)id, existing.Name, cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplateUpdated, (Guid)id, existing.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = existing.Name,
                ["typeKey"] = existing.TypeKey,
                ["issuancePolicyId"] = existing.IssuancePolicyId?.ToString(),
                ["issuerId"] = existing.IssuerId?.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CertificateTemplate?> SetIssuancePolicyAsync(CertificateTemplateId id, IssuancePolicyId? policyId, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (existing is null) return null;

        var previous = existing.IssuancePolicyId;
        if (previous == policyId) return existing;

        existing.IssuancePolicyId = policyId;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);

        // Names, not only ids, so the entry stays readable after a policy is deleted.
        await auditLog.LogAsync("TemplatePolicyChanged", performedBy, (Guid)id, existing.Name,
            $"{await DescribePolicyAsync(previous, cancellationToken)} -> {await DescribePolicyAsync(policyId, cancellationToken)}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplatePolicyChanged, (Guid)id, existing.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = existing.Name,
                ["typeKey"] = existing.TypeKey,
                ["issuancePolicyId"] = existing.IssuancePolicyId?.ToString(),
                ["issuerId"] = existing.IssuerId?.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CertificateTemplate?> SetIssuerAsync(CertificateTemplateId id, IssuerId? issuerId, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (existing is null) return null;

        var previous = existing.IssuerId;
        if (previous == issuerId) return existing;

        existing.IssuerId = issuerId;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("TemplateIssuerChanged", performedBy, (Guid)id, existing.Name,
            $"issuer: {await DescribeIssuerAsync(previous, cancellationToken)} -> {await DescribeIssuerAsync(issuerId, cancellationToken)}",
            cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplateIssuerChanged, (Guid)id, existing.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = existing.Name,
                ["typeKey"] = existing.TypeKey,
                ["issuancePolicyId"] = existing.IssuancePolicyId?.ToString(),
                ["issuerId"] = existing.IssuerId?.ToString()
            }), cancellationToken);
        return existing;
    }

    public async Task<CertificateTemplate?> SetPqcStageAsync(CertificateTemplateId id, PqcStage? stage, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (existing is null) return null;

        var previous = existing.PqcStageOverride;
        if (previous == stage) return existing;

        existing.PqcStageOverride = stage;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("TemplatePqcStageChanged", performedBy, (Guid)id, existing.Name,
            $"PQC stage: {previous?.ToString() ?? "CA default"} -> {stage?.ToString() ?? "CA default"}", cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplatePqcStageChanged, (Guid)id, existing.Name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = existing.Name,
                ["typeKey"] = existing.TypeKey,
                ["issuancePolicyId"] = existing.IssuancePolicyId?.ToString(),
                ["issuerId"] = existing.IssuerId?.ToString(),
                ["pqcStage"] = stage?.ToString()
            }), cancellationToken);
        return existing;
    }

    private async Task<string> DescribeIssuerAsync(IssuerId? issuerId, CancellationToken cancellationToken)
    {
        if (issuerId is not { } id) return "default";
        var name = await db.Issuers.AsNoTracking()
            .Where(i => i.Id == id)
            .Select(i => i.Name)
            .FirstOrDefaultAsync(cancellationToken);
        return name is null ? id.ToString() : $"'{name}' ({id})";
    }

    private async Task<string> DescribePolicyAsync(IssuancePolicyId? policyId, CancellationToken cancellationToken)
    {
        if (policyId is not { } id) return "none";
        var name = await db.IssuancePolicies.AsNoTracking()
            .Where(p => p.Id == id)
            .Select(p => p.Name)
            .FirstOrDefaultAsync(cancellationToken);
        return name is null ? id.ToString() : $"'{name}' ({id})";
    }

    public async Task<bool> DeleteAsync(CertificateTemplateId id, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await db.CertificateTemplates.FirstOrDefaultAsync(t => t.Id == id, cancellationToken);
        if (existing is null) return false;
        if (existing.IsBuiltIn)
            throw new InvalidOperationException("Built-in templates cannot be deleted.");

        // ACME and EST file every request under the template their settings key names. Deleting it
        // would leave both protocols pointing at nothing, which fails every enrollment closed.
        var settings = await db.Settings.AsNoTracking().SingleOrDefaultAsync(setting => setting.Id == 1, cancellationToken);
        if (settings is not null)
        {
            var protocols = new List<string>();
            if (string.Equals(settings.AcmeTemplateTypeKey, existing.TypeKey, StringComparison.Ordinal)) protocols.Add("ACME");
            if (string.Equals(settings.EstTemplateTypeKey, existing.TypeKey, StringComparison.Ordinal)) protocols.Add("EST");
            if (protocols.Count > 0)
                throw new Policies.IssuancePolicyConflictException(
                    $"Template '{existing.TypeKey}' is the {string.Join(" and ", protocols)} issuance template; point the setting elsewhere first.");
        }
        var name = existing.Name;
        db.CertificateTemplates.Remove(existing);
        await db.SaveChangesAsync(cancellationToken);
        await auditLog.LogAsync("TemplateDeleted", performedBy, (Guid)id, name, cancellationToken: cancellationToken);
        await webhookService.EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplateDeleted, (Guid)id, name,
            PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["templateName"] = name
            }), cancellationToken);
        return true;
    }
}
