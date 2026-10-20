using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Notices;

/// <summary>Read side of the Notices table for the API.</summary>
public interface INoticeQueryService
{
    /// <summary>One page of notices, newest first, with each certificate's name and metadata contact.</summary>
    Task<PagedResult<NoticeItem>> ListAsync(NoticeStatus? status, NoticeKind? kind, int page, int pageSize, CancellationToken cancellationToken = default);
}

internal sealed class NoticeQueryService(CertificateRequestDbContext db) : INoticeQueryService
{
    public async Task<PagedResult<NoticeItem>> ListAsync(
        NoticeStatus? status, NoticeKind? kind, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var query = db.Notices.AsNoTracking();
        if (status is { } wantedStatus) query = query.Where(n => n.Status == wantedStatus);
        if (kind is { } wantedKind) query = query.Where(n => n.Kind == wantedKind);

        var total = await query.CountAsync(cancellationToken);
        var notices = await query.OrderByDescending(n => n.CreatedAtUtc).ThenBy(n => n.Id)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken);

        var ids = notices.Select(n => n.RequestId).Distinct().ToList();
        var requests = await db.CertificateRequests.AsNoTracking()
            .Where(r => ids.Contains(r.Id))
            .Select(r => new { r.Id, r.CommonName, r.Metadata.OwnerTeam, r.Metadata.ContactEmail })
            .ToDictionaryAsync(r => r.Id, cancellationToken);

        return new PagedResult<NoticeItem>
        {
            Items = [.. notices.Select(n =>
            {
                requests.TryGetValue(n.RequestId, out var request);
                return new NoticeItem
                {
                    Id = n.Id, RequestId = n.RequestId, SourceRequestId = n.SourceRequestId, Kind = n.Kind, Step = n.Step,
                    Status = n.Status, CommonName = request?.CommonName, CreatedAtUtc = n.CreatedAtUtc, ResolvedAtUtc = n.ResolvedAtUtc,
                    OwnerTeam = request?.OwnerTeam, ContactEmail = request?.ContactEmail
                };
            })],
            TotalCount = total, Page = page, PageSize = pageSize
        };
    }
}
