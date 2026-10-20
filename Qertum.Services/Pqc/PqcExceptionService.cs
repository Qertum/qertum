using Microsoft.EntityFrameworkCore;
using Qertum.Services.Policies;

namespace Qertum.Services;

/// <summary>Revoking an exception that is already revoked. Maps to 409.</summary>
public sealed class PqcExceptionAlreadyRevokedException(PqcExceptionId id)
    : Exception($"PQC exception {id} is already revoked.");

/// <summary>Creates, lists and revokes PQC exceptions. Callers must have checked the admin role.</summary>
public interface IPqcExceptionService
{
    /// <summary>Active exceptions, or every exception when <paramref name="includeInactive"/>; soonest expiry first.</summary>
    Task<IReadOnlyList<PqcExceptionResponse>> ListAsync(bool includeInactive, CancellationToken cancellationToken = default);

    /// <summary>Grants an exception. Throws <see cref="NotFoundException"/> for an unknown template.</summary>
    Task<PqcExceptionResponse> CreateAsync(CreatePqcExceptionRequest request, string performedBy,
        string? performedBySubject, CancellationToken cancellationToken = default);

    /// <summary>Revokes an exception; null when it does not exist, throws when already revoked.</summary>
    Task<PqcExceptionResponse?> RevokeAsync(PqcExceptionId id, string performedBy, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
public sealed class PqcExceptionService(
    CertificateRequestDbContext db,
    IAuditLogService audit,
    IWebhookService webhooks,
    TimeProvider? timeProvider = null) : IPqcExceptionService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<IReadOnlyList<PqcExceptionResponse>> ListAsync(bool includeInactive, CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var query = db.PqcExceptions.AsNoTracking();
        if (!includeInactive)
            query = query.Where(e => e.RevokedAtUtc == null && e.ExpiresAtUtc > now);
        var rows = await query.ToListAsync(cancellationToken);
        return rows.OrderBy(e => e.ExpiresAtUtc).Select(e => ToResponse(e, now)).ToList();
    }

    /// <inheritdoc />
    public async Task<PqcExceptionResponse> CreateAsync(CreatePqcExceptionRequest request, string performedBy,
        string? performedBySubject, CancellationToken cancellationToken = default)
    {
        if (!await db.CertificateTemplates.AnyAsync(t => t.TypeKey == request.TemplateTypeKey, cancellationToken))
            throw new NotFoundException($"Template '{request.TemplateTypeKey}' does not exist.");

        var now = _clock.GetUtcNow().UtcDateTime;
        var entity = new PqcException
        {
            TemplateTypeKey = request.TemplateTypeKey,
            NamePattern = IssuancePolicyEvaluator.NormalizeDns(request.NamePattern)!,
            Family = request.Family,
            ExpiresAtUtc = DateTime.SpecifyKind(request.ExpiresAtUtc, DateTimeKind.Utc),
            Reason = request.Reason.Trim(),
            GrantedBy = performedBy,
            GrantedBySubject = performedBySubject,
            CreatedAtUtc = now
        };
        db.PqcExceptions.Add(entity);
        await db.SaveChangesAsync(cancellationToken);

        await audit.LogAsync("PqcExceptionCreated", performedBy, (Guid)entity.Id, entity.NamePattern,
            $"{entity.Family} on {entity.TemplateTypeKey} until {entity.ExpiresAtUtc:O}. Reason: {entity.Reason}",
            cancellationToken);
        await webhooks.EnqueueEventAsync(EventFor(WellKnownWebhookEvents.PqcExceptionCreated, entity, performedBy), cancellationToken);
        return ToResponse(entity, now);
    }

    /// <inheritdoc />
    public async Task<PqcExceptionResponse?> RevokeAsync(PqcExceptionId id, string performedBy, CancellationToken cancellationToken = default)
    {
        var entity = await db.PqcExceptions.FirstOrDefaultAsync(e => e.Id == id, cancellationToken);
        if (entity is null) return null;
        if (entity.RevokedAtUtc is not null) throw new PqcExceptionAlreadyRevokedException(id);

        var now = _clock.GetUtcNow().UtcDateTime;
        entity.RevokedBy = performedBy;
        entity.RevokedAtUtc = now;
        await db.SaveChangesAsync(cancellationToken);

        await audit.LogAsync("PqcExceptionRevoked", performedBy, (Guid)entity.Id, entity.NamePattern,
            $"{entity.Family} on {entity.TemplateTypeKey}, was due to expire {entity.ExpiresAtUtc:O}.", cancellationToken);
        await webhooks.EnqueueEventAsync(EventFor(WellKnownWebhookEvents.PqcExceptionRevoked, entity, performedBy), cancellationToken);
        return ToResponse(entity, now);
    }

    private static WebhookEvent EventFor(string name, PqcException entity, string performedBy) =>
        new(name, (Guid)entity.Id, entity.NamePattern, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["typeKey"] = entity.TemplateTypeKey,
                ["namePattern"] = entity.NamePattern,
                ["family"] = entity.Family.ToString(),
                ["expiresAtUtc"] = entity.ExpiresAtUtc.ToString("O")
            });

    private static PqcExceptionResponse ToResponse(PqcException e, DateTime now) => new()
    {
        Id = e.Id,
        TemplateTypeKey = e.TemplateTypeKey,
        NamePattern = e.NamePattern,
        Family = e.Family,
        ExpiresAtUtc = e.ExpiresAtUtc,
        Reason = e.Reason,
        GrantedBy = e.GrantedBy,
        CreatedAtUtc = e.CreatedAtUtc,
        RevokedBy = e.RevokedBy,
        RevokedAtUtc = e.RevokedAtUtc,
        IsActive = e.RevokedAtUtc is null && e.ExpiresAtUtc > now
    };
}
