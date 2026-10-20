using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Approvals;

/// <summary>The state machine behind two-person approval: request, decide, claim, release, read.</summary>
public interface IApprovalService
{
    /// <summary>True when <c>CaSettings.RequireTwoPersonApproval</c> is on. A read that never inserts the settings row.</summary>
    Task<bool> IsEnabledAsync(CancellationToken cancellationToken);

    /// <summary>Files a request. Refuses an unknown operation, a bad target or note, a caller without a subject, and a second open request.</summary>
    Task<ApprovalRequest> RequestAsync(ApprovalCaller caller, string operation, string? targetId, string? note, CancellationToken cancellationToken);

    /// <summary>Approves or denies a pending request. Administrators only, never the requester; one decider wins.</summary>
    Task<ApprovalRequest> DecideAsync(ApprovalRequestId id, ApprovalCaller decider, bool approve, string? note, CancellationToken cancellationToken);

    /// <summary>Uses up one approved, unexpired grant of <paramref name="subject"/> for the operation and target; null when there is none.</summary>
    Task<ApprovalRequestId?> ClaimAsync(string subject, string operation, string? targetId, CancellationToken cancellationToken);

    /// <summary>Gives a claimed grant back while its window is still open; does nothing afterwards.</summary>
    Task ReleaseAsync(ApprovalRequestId id, CancellationToken cancellationToken);

    /// <summary>One request, or null.</summary>
    Task<ApprovalRequest?> GetAsync(ApprovalRequestId id, CancellationToken cancellationToken);

    /// <summary>A page of requests, newest first. Administrators see all unless <paramref name="mineOnly"/>; others see their own.</summary>
    Task<PagedResult<ApprovalRequest>> ListAsync(ApprovalCaller caller, ApprovalStatus? status, bool mineOnly, int page, int pageSize, CancellationToken cancellationToken);

    /// <summary>The status as of now: a stored <c>Pending</c> or <c>Approved</c> past its time reads <c>Expired</c>.</summary>
    ApprovalStatus EffectiveStatus(ApprovalRequest request);
}

/// <inheritdoc cref="IApprovalService" />
public sealed class ApprovalService(
    CertificateRequestDbContext db,
    IOptions<ApprovalOptions> options,
    TimeProvider? timeProvider = null) : IApprovalService
{
    private const int MaxNoteLength = 500;
    private const int MaxTargetLength = 64;
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly ApprovalOptions _options = options.Value;

    private DateTime Now => _clock.GetUtcNow().UtcDateTime;

    private DateTime PendingCutoff(DateTime now) => now.AddHours(-_options.RequestTtlHours);

    /// <inheritdoc />
    public async Task<bool> IsEnabledAsync(CancellationToken cancellationToken) =>
        await db.Settings.AsNoTracking().Where(s => s.Id == 1).Select(s => s.RequireTwoPersonApproval)
            .FirstOrDefaultAsync(cancellationToken);

    /// <inheritdoc />
    public ApprovalStatus EffectiveStatus(ApprovalRequest request) => request.Status switch
    {
        ApprovalStatus.Pending when request.RequestedAtUtc <= PendingCutoff(Now) => ApprovalStatus.Expired,
        ApprovalStatus.Approved when request.GrantExpiresAtUtc is not { } until || until <= Now => ApprovalStatus.Expired,
        var stored => stored
    };

    /// <inheritdoc />
    public async Task<ApprovalRequest> RequestAsync(
        ApprovalCaller caller, string operation, string? targetId, string? note, CancellationToken cancellationToken)
    {
        var subject = RequireSubject(caller);
        if (!ApprovalOperations.IsKnown(operation))
            throw new ApprovalException(ApprovalError.Invalid, "The operation is not one that needs approval.");
        targetId = ApprovalTargets.Normalize(targetId);
        if (ApprovalOperations.NeedsTarget(operation) && targetId is null)
            throw new ApprovalException(ApprovalError.Invalid, "This operation needs a target.");
        if (!ApprovalOperations.NeedsTarget(operation) && targetId is not null)
            throw new ApprovalException(ApprovalError.Invalid, "This operation has no target.");
        if (targetId is { Length: > MaxTargetLength })
            throw new ApprovalException(ApprovalError.Invalid, "The target is too long.");
        note = NormalizeNote(note);

        var now = Now;
        // Rows of this key that ran out of time but have not been swept yet would block the unique "one open request" index.
        await db.ApprovalRequests
            .Where(a => a.RequestedBySubject == subject && a.Operation == operation && a.TargetId == targetId
                        && ((a.Status == ApprovalStatus.Pending && a.RequestedAtUtc <= PendingCutoff(now))
                            || (a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc <= now)))
            .ExecuteUpdateAsync(set => set.SetProperty(a => a.Status, ApprovalStatus.Expired), cancellationToken);
        var open = await db.ApprovalRequests.AsNoTracking()
            .Where(a => a.RequestedBySubject == subject && a.Operation == operation && a.TargetId == targetId
                        && ((a.Status == ApprovalStatus.Pending && a.RequestedAtUtc > PendingCutoff(now))
                            || (a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc > now)))
            .AnyAsync(cancellationToken);
        if (open)
            throw new ApprovalException(ApprovalError.Conflict, "An approval for this operation and target is already open.");

        var request = new ApprovalRequest
        {
            Operation = operation, TargetId = targetId, Note = note,
            RequestedBySubject = subject, RequestedByName = caller.Name, RequestedAtUtc = now,
            Status = ApprovalStatus.Pending
        };
        db.ApprovalRequests.Add(request);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (ex.InnerException is Microsoft.Data.Sqlite.SqliteException { SqliteErrorCode: 19 })
        {
            // Lost the race to an identical request filed at the same moment: the database allows one open request per key.
            throw new ApprovalException(ApprovalError.Conflict, "An approval for this operation and target is already open.");
        }

        return request;
    }

    /// <inheritdoc />
    public async Task<ApprovalRequest> DecideAsync(
        ApprovalRequestId id, ApprovalCaller decider, bool approve, string? note, CancellationToken cancellationToken)
    {
        var subject = RequireSubject(decider);
        if (!decider.IsAdmin)
            throw new ApprovalException(ApprovalError.NotAllowed, "Only an administrator can decide an approval.");
        note = NormalizeNote(note);

        var existing = await db.ApprovalRequests.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken)
            ?? throw new ApprovalException(ApprovalError.NotFound, "The approval request does not exist.");
        if (existing.RequestedBySubject == subject)
            throw new ApprovalException(ApprovalError.NotAllowed, "You cannot decide your own request.");

        var now = Now;
        var cutoff = PendingCutoff(now);
        var status = approve ? ApprovalStatus.Approved : ApprovalStatus.Denied;
        DateTime? grantUntil = approve ? now.AddMinutes(_options.GrantWindowMinutes) : null;
        var changed = await db.ApprovalRequests
            .Where(a => a.Id == id && a.Status == ApprovalStatus.Pending && a.RequestedAtUtc > cutoff)
            .ExecuteUpdateAsync(set => set
                .SetProperty(a => a.Status, status)
                .SetProperty(a => a.DecidedBySubject, subject)
                .SetProperty(a => a.DecidedByName, decider.Name)
                .SetProperty(a => a.DecidedAtUtc, now)
                .SetProperty(a => a.DecisionNote, note)
                .SetProperty(a => a.GrantExpiresAtUtc, grantUntil), cancellationToken);
        if (changed == 0)
            throw new ApprovalException(ApprovalError.Conflict, "The request is no longer pending.");

        return await db.ApprovalRequests.AsNoTracking().FirstAsync(a => a.Id == id, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ApprovalRequestId?> ClaimAsync(
        string subject, string operation, string? targetId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(subject))
            return null;
        targetId = ApprovalTargets.Normalize(targetId);
        // A few candidates at most (one open request per caller, operation and target); losing the race for one means no grant.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var now = Now;
            var candidate = await db.ApprovalRequests.AsNoTracking()
                .Where(a => a.RequestedBySubject == subject && a.Operation == operation && a.TargetId == targetId
                            && a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc > now)
                .OrderBy(a => a.GrantExpiresAtUtc)
                .Select(a => (ApprovalRequestId?)a.Id)
                .FirstOrDefaultAsync(cancellationToken);
            if (candidate is not { } id)
                return null;

            var changed = await db.ApprovalRequests
                .Where(a => a.Id == id && a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc > now)
                .ExecuteUpdateAsync(set => set
                    .SetProperty(a => a.Status, ApprovalStatus.Used)
                    .SetProperty(a => a.UsedAtUtc, now), cancellationToken);
            if (changed == 1)
                return id;
        }

        return null;
    }

    /// <inheritdoc />
    public async Task ReleaseAsync(ApprovalRequestId id, CancellationToken cancellationToken)
    {
        var now = Now;
        await db.ApprovalRequests
            .Where(a => a.Id == id && a.Status == ApprovalStatus.Used && a.GrantExpiresAtUtc > now)
            .ExecuteUpdateAsync(set => set
                .SetProperty(a => a.Status, ApprovalStatus.Approved)
                .SetProperty(a => a.UsedAtUtc, (DateTime?)null), cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ApprovalRequest?> GetAsync(ApprovalRequestId id, CancellationToken cancellationToken) =>
        await db.ApprovalRequests.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken);

    /// <inheritdoc />
    public async Task<PagedResult<ApprovalRequest>> ListAsync(
        ApprovalCaller caller, ApprovalStatus? status, bool mineOnly, int page, int pageSize, CancellationToken cancellationToken)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 200);
        var now = Now;
        var cutoff = PendingCutoff(now);
        var query = db.ApprovalRequests.AsNoTracking().AsQueryable();
        if (!caller.IsAdmin || mineOnly)
        {
            var subject = caller.Subject ?? string.Empty;
            query = query.Where(a => a.RequestedBySubject == subject);
        }

        query = status switch
        {
            ApprovalStatus.Pending => query.Where(a => a.Status == ApprovalStatus.Pending && a.RequestedAtUtc > cutoff),
            ApprovalStatus.Approved => query.Where(a => a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc > now),
            ApprovalStatus.Expired => query.Where(a => a.Status == ApprovalStatus.Expired
                || (a.Status == ApprovalStatus.Pending && a.RequestedAtUtc <= cutoff)
                || (a.Status == ApprovalStatus.Approved && a.GrantExpiresAtUtc <= now)),
            { } other => query.Where(a => a.Status == other),
            null => query
        };

        var total = await query.CountAsync(cancellationToken);
        var items = await query.OrderByDescending(a => a.RequestedAtUtc).Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(cancellationToken);
        return new PagedResult<ApprovalRequest> { Items = items, TotalCount = total, Page = page, PageSize = pageSize };
    }

    private static string RequireSubject(ApprovalCaller caller) =>
        string.IsNullOrWhiteSpace(caller.Subject)
            ? throw new ApprovalException(ApprovalError.NotAllowed, "This token has no subject and cannot take part in an approval.")
            : caller.Subject;

    // Plain text: trimmed, line breaks normalized to \n, nothing else that is a control character (a terminal would act on it).
    private static string? NormalizeNote(string? note)
    {
        if (string.IsNullOrWhiteSpace(note))
            return null;
        var text = note.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Trim();
        if (text.Length > MaxNoteLength)
            throw new ApprovalException(ApprovalError.Invalid, string.Create(CultureInfo.InvariantCulture, $"The note is longer than {MaxNoteLength} characters."));
        if (text.Any(c => char.IsControl(c) && c != '\n'))
            throw new ApprovalException(ApprovalError.Invalid, "The note contains a control character.");
        return text;
    }
}
