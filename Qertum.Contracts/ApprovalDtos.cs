namespace Qertum.Services;

/// <summary>Body of <c>POST /v1/approvals</c>.</summary>
/// <param name="Operation">One of the operation keys (for example <c>bulk-revoke</c>).</param>
/// <param name="TargetId">The id of what the operation acts on; omitted only for creating an intermediate issuer.</param>
/// <param name="Note">What the requester will do, plain text, at most 500 characters.</param>
public sealed record RequestApprovalRequest(string Operation, string? TargetId = null, string? Note = null);

/// <summary>Body of <c>POST /v1/approvals/{id}/approve</c> and <c>/deny</c>.</summary>
/// <param name="Note">The decider's note, plain text, at most 500 characters.</param>
public sealed record DecideApprovalRequest(string? Note = null);

/// <summary>An approval request as the API returns it.</summary>
/// <param name="Id">Approval identifier.</param>
/// <param name="Operation">Operation key.</param>
/// <param name="TargetId">The target's id, or null.</param>
/// <param name="TargetLabel">A readable name for the target (certificate common name, issuer or policy name, the bulk operation), or null.</param>
/// <param name="Note">The requester's note.</param>
/// <param name="RequestedByName">Who asked.</param>
/// <param name="RequestedAtUtc">When.</param>
/// <param name="Status">Effective status: a pending or approved request past its time reads <c>Expired</c>.</param>
/// <param name="DecidedByName">Who decided.</param>
/// <param name="DecidedAtUtc">When.</param>
/// <param name="DecisionNote">The decider's note.</param>
/// <param name="GrantExpiresAtUtc">End of the window in which an approved grant can be used.</param>
/// <param name="UsedAtUtc">When the grant was used.</param>
/// <param name="IsMine">Whether the caller is the one who asked (so cannot decide it).</param>
public sealed record ApprovalResponse(
    ApprovalRequestId Id, string Operation, string? TargetId, string? TargetLabel, string? Note,
    string RequestedByName, DateTime RequestedAtUtc, ApprovalStatus Status,
    string? DecidedByName, DateTime? DecidedAtUtc, string? DecisionNote, DateTime? GrantExpiresAtUtc, DateTime? UsedAtUtc,
    bool IsMine = false);
