using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services.Lifecycle;

namespace Qertum.Services.Est;

/// <summary>An EST credential's diagnostic events, newest first. Needs settings.edit at the route.</summary>
public interface IEstCredentialActivityService
{
    /// <summary>A page of events, or null when the credential does not exist.</summary>
    Task<PagedResult<TimelineEntry>?> GetAsync(Guid credentialId, int page, int pageSize,
        CancellationToken cancellationToken = default);
}

public sealed class EstCredentialActivityService(CertificateRequestDbContext db) : IEstCredentialActivityService
{
    public async Task<PagedResult<TimelineEntry>?> GetAsync(Guid credentialId, int page, int pageSize,
        CancellationToken cancellationToken = default)
    {
        if (!await db.EstEnrollmentCredentials.AnyAsync(c => c.Id == credentialId, cancellationToken))
            return null;

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.LifecycleEvents.AsNoTracking()
            .Where(e => e.SubjectType == LifecycleSubjectTypes.EstCredential && e.SubjectId == credentialId);
        var total = await query.CountAsync(cancellationToken);
        var events = await query.OrderByDescending(e => e.OccurredAtUtc)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken);

        // "Enrolled" says the request was filed; whether it then waits for approval, was issued or
        // was rejected is read from the request now, which is what tells the two apart.
        var requestIds = events.Select(RequestIdOf).OfType<Guid>().Distinct().ToList();
        var strongIds = requestIds.Select(g => new CertificateRequestId(g)).ToList();
        var statuses = requestIds.Count == 0
            ? new Dictionary<Guid, CertificateRequestStatus>()
            : (await db.CertificateRequests.AsNoTracking()
                    .Where(r => strongIds.Contains(r.Id))
                    .Select(r => new { r.Id, r.Status })
                    .ToListAsync(cancellationToken))
                .ToDictionary(r => (Guid)r.Id, r => r.Status);

        return new PagedResult<TimelineEntry>
        {
            Items = events.Select(e =>
            {
                var entry = Acme.AcmeOrderQueryService.ToEntry(e);
                if (RequestIdOf(e) is not { } requestId) return entry;
                return new TimelineEntry
                {
                    OccurredAtUtc = entry.OccurredAtUtc, Kind = entry.Kind, Action = entry.Action,
                    PerformedBy = entry.PerformedBy, Detail = entry.Detail, Hint = entry.Hint,
                    RelatedRequestId = requestId,
                    Category = statuses.TryGetValue(requestId, out var status) ? status.ToString() : "Removed",
                };
            }).ToList(),
            TotalCount = total,
            Page = page,
            PageSize = pageSize,
        };
    }

    private static Guid? RequestIdOf(LifecycleEvent e)
    {
        if (e.DataJson is null) return null;
        try
        {
            using var doc = JsonDocument.Parse(e.DataJson);
            return doc.RootElement.TryGetProperty("certificateRequestId", out var id) && id.TryGetGuid(out var guid)
                ? guid
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
