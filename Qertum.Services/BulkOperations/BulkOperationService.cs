using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Policies;

namespace Qertum.Services.BulkOperations;

/// <summary>
/// Bulk revoke and renew. Preview freezes the eligible set into a <see cref="BulkOperation"/>; execute
/// (see <see cref="IBulkOperationService"/>) hands it to the background job. Writes only through
/// <c>ExecuteUpdate</c>/inserts of its own tables; the per-certificate work is done later, one item at
/// a time, by the single-item service paths.
/// </summary>
public sealed class BulkOperationService(
    CertificateRequestDbContext db,
    IOptions<BulkOperationsOptions> options,
    IAuditLogService auditLog,
    IBackgroundJobQueue jobs,
    TimeProvider? timeProvider = null) : IBulkOperationService
{
    private const string LikeEscape = "\\";
    private const int InsertChunk = 1000;
    private const int SampleSize = 20;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<BulkOperationPreview> PreviewAsync(PreviewBulkOperationRequest request, BulkActor actor, CancellationToken ct = default)
    {
        var filter = request.Filter ?? new BulkOperationFilter();
        if (filter.All && filter.HasCriterion)
            throw new BulkOperationException(422, "'all' cannot be combined with another filter field.");
        if (!filter.All && !filter.HasCriterion)
            throw new BulkOperationException(422, "Choose at least one filter field, or set 'all' to select every eligible certificate.");
        if (request.Kind == BulkOperationKind.Revoke && string.IsNullOrWhiteSpace(request.Reason))
            throw new BulkOperationException(422, "A revocation reason is required.");

        var now = _clock.GetUtcNow().UtcDateTime;
        var matches = ApplyFilter(db.CertificateRequests.AsNoTracking(), filter, now);

        var excluded = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var notIssued = await matches.CountAsync(r => r.Status != CertificateRequestStatus.Issued, ct);
        if (notIssued > 0) excluded["not-issued"] = notIssued;

        var eligible = matches.Where(r => r.Status == CertificateRequestStatus.Issued);

        if (request.Kind == BulkOperationKind.Renew)
        {
            var activeRenewalSources = db.CertificateRequests
                .Where(r => r.RenewedFromId.HasValue && r.Status != CertificateRequestStatus.Rejected && r.Status != CertificateRequestStatus.Revoked)
                .Select(r => r.RenewedFromId!.Value);
            var caTypeKeys = (await db.CertificateTemplates.AsNoTracking()
                    .Select(t => new { t.TypeKey, t.KeyUsagesJson }).ToListAsync(ct))
                .Where(t => CaCapableTemplate.IsCaCapable(t.KeyUsagesJson))
                .Select(t => t.TypeKey)
                .ToList();

            // Counted in the order the reasons are reported; a request is counted under the first that applies.
            var clientKey = await eligible.CountAsync(r => r.CsrPem != null, ct);
            eligible = eligible.Where(r => r.CsrPem == null);
            var ca = await eligible.CountAsync(r => caTypeKeys.Contains(r.Type!), ct);
            eligible = eligible.Where(r => !caTypeKeys.Contains(r.Type!));
            var active = await eligible.CountAsync(r => activeRenewalSources.Contains(r.Id), ct);
            eligible = eligible.Where(r => !activeRenewalSources.Contains(r.Id));

            if (clientKey > 0) excluded["client-key"] = clientKey;
            if (ca > 0) excluded["ca-capable"] = ca;
            if (active > 0) excluded["active-renewal"] = active;
        }

        // Counted before the ids are loaded, so a filter that matches the whole table is refused without reading it.
        var matched = await eligible.CountAsync(ct);
        if (matched == 0)
            throw new BulkOperationException(422, "No eligible certificate matches the filter." + DescribeExclusions(excluded));
        if (matched > options.Value.MaxItems)
            throw new BulkOperationException(422,
                $"The filter matches {matched.ToString(CultureInfo.InvariantCulture)} certificates, more than the limit of {options.Value.MaxItems.ToString(CultureInfo.InvariantCulture)}. Narrow the filter.");
        var ids = await eligible.OrderBy(r => r.CreatedAtUtc).ThenBy(r => r.Id).Select(r => r.Id).ToListAsync(ct);

        var operation = new BulkOperation
        {
            Kind = request.Kind,
            Status = BulkOperationStatus.Previewed,
            FilterJson = JsonSerializer.Serialize(filter, Json),
            Reason = request.Kind == BulkOperationKind.Revoke ? request.Reason!.Trim() : null,
            CreatedBy = actor.Name,
            CreatedBySubject = actor.Subject,
            CreatedAtUtc = now,
            ItemCount = ids.Count,
            ExcludedJson = JsonSerializer.Serialize(excluded, Json)
        };

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        db.BulkOperations.Add(operation);
        await db.SaveChangesAsync(ct);
        foreach (var chunk in ids.Chunk(InsertChunk))
        {
            db.BulkOperationItems.AddRange(chunk.Select(id => new BulkOperationItem { OperationId = operation.Id, RequestId = id }));
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        await tx.CommitAsync(ct);

        await auditLog.LogAsync("BulkOperationPreviewed", actor.Name, (Guid)operation.Id, operation.Kind.ToString(),
            $"Filter: {(filter.All ? "all" : operation.FilterJson)}; items: {ids.Count}; excluded: {operation.ExcludedJson}"
            + (operation.Reason is null ? "" : $"; reason: {operation.Reason}"), ct);

        var sample = await ItemViewsAsync(operation.Id, outcome: null, page: 1, pageSize: SampleSize, ct);
        return new BulkOperationPreview { Operation = ToView(operation), Sample = sample.Items };
    }

    /// <inheritdoc />
    public async Task<BulkOperationView> ExecuteAsync(BulkOperationId id, int confirmCount, BulkActor actor, CancellationToken ct = default)
    {
        var operation = await db.BulkOperations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == id, ct)
            ?? throw new BulkOperationException(404, "No such bulk operation.");
        if (operation.Status != BulkOperationStatus.Previewed)
            throw new BulkOperationException(409, $"The operation is {operation.Status}, not Previewed.");

        var now = _clock.GetUtcNow().UtcDateTime;
        if (now > operation.CreatedAtUtc.AddMinutes(options.Value.PreviewTtlMinutes))
        {
            await db.BulkOperations.Where(o => o.Id == id && o.Status == BulkOperationStatus.Previewed)
                .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, BulkOperationStatus.Expired), ct);
            throw new BulkOperationException(410, "The preview has expired. Preview again.");
        }
        if (confirmCount != operation.ItemCount)
            throw new BulkOperationException(409,
                $"confirmCount {confirmCount.ToString(CultureInfo.InvariantCulture)} does not match the {operation.ItemCount.ToString(CultureInfo.InvariantCulture)} items previewed.");

        var snapshot = JsonSerializer.Serialize(new BulkCallerSnapshot(actor.Subject, actor.Name, actor.IsAdmin, actor.HoldsCaPermission), Json);
        // The conditional update is the guard against a double click: only one caller flips Previewed to Running.
        var flipped = await db.BulkOperations.Where(o => o.Id == id && o.Status == BulkOperationStatus.Previewed)
            .ExecuteUpdateAsync(s => s
                .SetProperty(o => o.Status, BulkOperationStatus.Running)
                .SetProperty(o => o.ExecutedBy, actor.Name)
                .SetProperty(o => o.ExecutedAtUtc, now)
                .SetProperty(o => o.CallerSnapshotJson, snapshot), ct);
        if (flipped == 0)
            throw new BulkOperationException(409, "The operation was started or cancelled by someone else.");

        BackgroundJob? job;
        try
        {
            job = await jobs.EnqueueAsync(WellKnownJobTypes.BulkOperation, $"bulk-operation:{id}", actor.Name,
                $"bulk {operation.Kind}", JsonSerializer.Serialize(new { operationId = id.ToString() }, Json), ct);
        }
        catch
        {
            await RevertToPreviewedAsync(id);
            throw;
        }
        if (job is null)
        {
            // Running with no job would never finish and could not be cancelled: hand the preview back.
            await RevertToPreviewedAsync(id);
            throw new BulkOperationException(409, "A job for this operation already exists.");
        }

        await auditLog.LogAsync("BulkOperationStarted", actor.Name, (Guid)id, operation.Kind.ToString(),
            $"Items: {operation.ItemCount}" + (operation.Reason is null ? "" : $"; reason: {operation.Reason}"), ct);
        return (await GetAsync(id, ct))!;
    }

    private Task<int> RevertToPreviewedAsync(BulkOperationId id) =>
        db.BulkOperations.Where(o => o.Id == id && o.Status == BulkOperationStatus.Running)
            .ExecuteUpdateAsync(s => s
                .SetProperty(o => o.Status, BulkOperationStatus.Previewed)
                .SetProperty(o => o.ExecutedBy, (string?)null)
                .SetProperty(o => o.ExecutedAtUtc, (DateTime?)null)
                .SetProperty(o => o.CallerSnapshotJson, (string?)null), CancellationToken.None);

    /// <inheritdoc />
    public async Task<BulkOperationView> CancelAsync(BulkOperationId id, BulkActor actor, CancellationToken ct = default)
    {
        var operation = await db.BulkOperations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == id, ct)
            ?? throw new BulkOperationException(404, "No such bulk operation.");
        var flipped = await db.BulkOperations.Where(o => o.Id == id && o.Status == BulkOperationStatus.Previewed)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, BulkOperationStatus.Cancelled), ct);
        if (flipped == 0)
            throw new BulkOperationException(409, $"The operation is {operation.Status}, not Previewed.");
        await auditLog.LogAsync("BulkOperationCancelled", actor.Name, (Guid)id, operation.Kind.ToString(), $"Items: {operation.ItemCount}", ct);
        return (await GetAsync(id, ct))!;
    }

    /// <inheritdoc />
    public async Task<BulkOperationView?> GetAsync(BulkOperationId id, CancellationToken ct = default)
    {
        var operation = await db.BulkOperations.AsNoTracking().SingleOrDefaultAsync(o => o.Id == id, ct);
        return operation is null ? null : ToView(operation);
    }

    /// <inheritdoc />
    public async Task<PagedResult<BulkOperationView>> ListAsync(int page, int pageSize, string? creatorSubject, CancellationToken ct = default)
    {
        (page, pageSize) = (Math.Max(page, 1), Math.Clamp(pageSize, 1, 200));
        var query = db.BulkOperations.AsNoTracking();
        if (creatorSubject is not null) query = query.Where(o => o.CreatedBySubject == creatorSubject);
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(o => o.CreatedAtUtc).ThenBy(o => o.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<BulkOperationView> { Items = rows.Select(ToView).ToList(), TotalCount = total, Page = page, PageSize = pageSize };
    }

    /// <inheritdoc />
    public async Task<PagedResult<BulkOperationItemView>?> GetItemsAsync(
        BulkOperationId id, BulkItemOutcome? outcome, int page, int pageSize, CancellationToken ct = default)
    {
        if (!await db.BulkOperations.AnyAsync(o => o.Id == id, ct)) return null;
        return await ItemViewsAsync(id, outcome, Math.Max(page, 1), Math.Clamp(pageSize, 1, 200), ct);
    }

    internal static BulkOperationView ToView(BulkOperation o) => new()
    {
        Id = o.Id,
        Kind = o.Kind,
        Status = o.Status,
        Filter = SafeFilter(o.FilterJson),
        Reason = o.Reason,
        CreatedBy = o.CreatedBy,
        CreatedBySubject = o.CreatedBySubject,
        CreatedAtUtc = o.CreatedAtUtc,
        ExecutedBy = o.ExecutedBy,
        ExecutedAtUtc = o.ExecutedAtUtc,
        FinishedAtUtc = o.FinishedAtUtc,
        ItemCount = o.ItemCount,
        DoneCount = o.DoneCount,
        SkippedCount = o.SkippedCount,
        FailedCount = o.FailedCount,
        Excluded = SafeExcluded(o.ExcludedJson)
    };

    private static BulkOperationFilter SafeFilter(string json)
    {
        try { return JsonSerializer.Deserialize<BulkOperationFilter>(json, Json) ?? new BulkOperationFilter(); }
        catch (JsonException) { return new BulkOperationFilter(); }
    }

    private static Dictionary<string, int> SafeExcluded(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return JsonSerializer.Deserialize<Dictionary<string, int>>(json, Json) ?? []; }
        catch (JsonException) { return []; }
    }

    private static string DescribeExclusions(IReadOnlyDictionary<string, int> excluded) =>
        excluded.Count == 0
            ? ""
            : " Left out: " + string.Join(", ", excluded.Select(e => $"{e.Key} {e.Value.ToString(CultureInfo.InvariantCulture)}")) + ".";

    private static IQueryable<CertificateRequest> ApplyFilter(IQueryable<CertificateRequest> query, BulkOperationFilter filter, DateTime now)
    {
        if (filter.All) return query;
        if (filter.IssuerId is { } issuer) query = query.Where(r => r.IssuerId == issuer);
        if (!string.IsNullOrWhiteSpace(filter.TemplateKey)) { var key = filter.TemplateKey.Trim(); query = query.Where(r => r.Type == key); }
        if (!string.IsNullOrWhiteSpace(filter.OwnerSubject)) { var owner = filter.OwnerSubject.Trim(); query = query.Where(r => r.RequestedBySubject == owner); }
        var before = filter.ValidToBefore ?? (filter.ExpiresWithinDays is { } days ? now.AddDays(days) : (DateTime?)null);
        if (before is { } b) query = query.Where(r => r.ValidTo != null && r.ValidTo <= b);
        if (filter.ValidToAfter is { } after) query = query.Where(r => r.ValidTo != null && r.ValidTo >= after);
        if (!string.IsNullOrWhiteSpace(filter.CommonNameContains))
        {
            var pattern = $"%{EscapeLike(filter.CommonNameContains.Trim())}%";
            query = query.Where(r => EF.Functions.Like(r.CommonName, pattern, LikeEscape));
        }
        return query;
    }

    private static string EscapeLike(string value) =>
        value.Replace(LikeEscape, LikeEscape + LikeEscape).Replace("%", LikeEscape + "%").Replace("_", LikeEscape + "_");

    private async Task<PagedResult<BulkOperationItemView>> ItemViewsAsync(
        BulkOperationId id, BulkItemOutcome? outcome, int page, int pageSize, CancellationToken ct)
    {
        var items = db.BulkOperationItems.AsNoTracking().Where(i => i.OperationId == id);
        if (outcome is { } o) items = items.Where(i => i.Outcome == o);
        var total = await items.CountAsync(ct);
        var rows = await items
            .OrderBy(i => i.RequestId)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .GroupJoin(db.CertificateRequests.AsNoTracking(), i => i.RequestId, r => r.Id, (i, rs) => new { Item = i, Requests = rs })
            .SelectMany(x => x.Requests.DefaultIfEmpty(), (x, r) => new BulkOperationItemView
            {
                RequestId = x.Item.RequestId,
                CommonName = r != null ? r.CommonName : "",
                Outcome = x.Item.Outcome,
                Detail = x.Item.Detail,
                ResultRequestId = x.Item.ResultRequestId
            })
            .ToListAsync(ct);
        return new PagedResult<BulkOperationItemView> { Items = rows, TotalCount = total, Page = page, PageSize = pageSize };
    }
}
