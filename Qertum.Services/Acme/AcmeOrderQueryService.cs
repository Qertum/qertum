using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services.Lifecycle;

namespace Qertum.Services.Acme;

/// <summary>Read-only views of ACME orders for operators. Needs settings.edit at the route.</summary>
public interface IAcmeOrderQueryService
{
    Task<PagedResult<AcmeOrderSummary>> ListAsync(string? search, bool failingOnly, int page, int pageSize,
        CancellationToken cancellationToken = default);

    Task<AcmeOrderDetail?> GetAsync(Guid id, CancellationToken cancellationToken = default);
}

public sealed class AcmeOrderQueryService(CertificateRequestDbContext db, TimeProvider? timeProvider = null) : IAcmeOrderQueryService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private static readonly JsonSerializerOptions IdentifierJson = new() { PropertyNameCaseInsensitive = true };

    public async Task<PagedResult<AcmeOrderSummary>> ListAsync(string? search, bool failingOnly, int page, int pageSize,
        CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);
        var now = _clock.GetUtcNow().UtcDateTime;

        var query = db.AcmeOrders.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            var pattern = "%" + term.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
            query = Guid.TryParse(term, out var accountId)
                ? query.Where(o => o.AccountId == accountId || o.Id == accountId)
                : query.Where(o => EF.Functions.Like(o.IdentifiersJson, pattern, "\\"));
        }
        if (failingOnly)
            query = query.Where(o =>
                o.Status == "invalid" ||
                (o.Status != "valid" && o.ExpiresAtUtc <= now) ||
                db.LifecycleEvents.Any(e => e.SubjectType == LifecycleSubjectTypes.AcmeOrder && e.SubjectId == o.Id
                                            && e.Action == DiagnosticActions.ChallengeAttemptFailed));

        var total = await query.CountAsync(cancellationToken);
        var orders = await query.OrderByDescending(o => o.CreatedAtUtc)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken);

        var ids = orders.Select(o => o.Id).ToList();
        var lastFailures = (await db.LifecycleEvents.AsNoTracking()
                .Where(e => e.SubjectType == LifecycleSubjectTypes.AcmeOrder && ids.Contains(e.SubjectId)
                            && e.Action == DiagnosticActions.ChallengeAttemptFailed)
                .ToListAsync(cancellationToken))
            .GroupBy(e => e.SubjectId)
            .ToDictionary(g => g.Key, g => g.MaxBy(e => e.OccurredAtUtc)!);

        return new PagedResult<AcmeOrderSummary>
        {
            Items = orders.Select(o => Summarize(o, lastFailures.GetValueOrDefault(o.Id), now)).ToList(),
            TotalCount = total,
            Page = page,
            PageSize = pageSize,
        };
    }

    public async Task<AcmeOrderDetail?> GetAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var order = await db.AcmeOrders.AsNoTracking()
            .Include(o => o.Authorizations).ThenInclude(a => a.Challenges)
            .FirstOrDefaultAsync(o => o.Id == id, cancellationToken);
        if (order is null) return null;

        var events = await db.LifecycleEvents.AsNoTracking()
            .Where(e => e.SubjectType == LifecycleSubjectTypes.AcmeOrder && e.SubjectId == id)
            .OrderBy(e => e.OccurredAtUtc)
            .ToListAsync(cancellationToken);
        var lastFailure = events.LastOrDefault(e => e.Action == DiagnosticActions.ChallengeAttemptFailed);

        return new AcmeOrderDetail
        {
            Order = Summarize(order, lastFailure, _clock.GetUtcNow().UtcDateTime),
            Authorizations = order.Authorizations
                .OrderBy(a => a.IdentifierValue)
                .Select(a => new AcmeAuthorizationView
                {
                    Identifier = a.IdentifierValue,
                    Wildcard = a.Wildcard,
                    Status = AcmeEffectiveStatus.Authorization(a, _clock.GetUtcNow().UtcDateTime),
                    ExpiresAtUtc = a.ExpiresAtUtc,
                    Challenges = a.Challenges.OrderBy(c => c.Type).Select(c => new AcmeChallengeView
                    {
                        Type = c.Type,
                        Status = c.Status,
                        Attempts = c.ValidationAttempts,
                        NextAttemptAfterUtc = c.Status == "processing" && c.NextAttemptAfterUtc > DateTime.MinValue
                            ? c.NextAttemptAfterUtc
                            : null,
                        ValidatedAtUtc = c.ValidatedAtUtc,
                    }).ToList(),
                }).ToList(),
            History = events.Select(ToEntry).ToList(),
        };
    }

    /// <summary>A diagnostic event as a timeline entry, with its category's hint.</summary>
    internal static TimelineEntry ToEntry(LifecycleEvent e) => new()
    {
        OccurredAtUtc = e.OccurredAtUtc,
        Kind = TimelineEntryKind.Diagnostic,
        Action = e.Action,
        Category = e.Category,
        PerformedBy = e.PerformedBy,
        Detail = e.Detail,
        Hint = DiagnosticHints.For(e.Category),
    };

    private static AcmeOrderSummary Summarize(AcmeOrder order, LifecycleEvent? lastFailure, DateTime now) => new()
    {
        Id = order.Id,
        AccountId = order.AccountId,
        Identifiers = ParseIdentifiers(order.IdentifiersJson),
        Status = AcmeEffectiveStatus.Order(order, now),
        CreatedAtUtc = order.CreatedAtUtc,
        ExpiresAtUtc = order.ExpiresAtUtc,
        CertificateRequestId = order.CertificateRequestId,
        LastFailureCategory = lastFailure?.Category,
        LastFailureDetail = lastFailure?.Detail,
        LastFailureAtUtc = lastFailure?.OccurredAtUtc,
    };

    // Written lowercase by new-order; read case-insensitively, the same rule finalize follows.
    private static List<string> ParseIdentifiers(string json)
    {
        try
        {
            return (JsonSerializer.Deserialize<List<IdentifierDto>>(json, IdentifierJson) ?? [])
                .Select(i => i.Value).Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private sealed record IdentifierDto(string Type, string Value);
}
