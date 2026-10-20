namespace Qertum.Services.Approvals;

/// <summary>Why an approval request or decision was refused.</summary>
public enum ApprovalError
{
    /// <summary>The caller may not do this (no subject, not an administrator, deciding their own request).</summary>
    NotAllowed,

    /// <summary>The request or its target does not exist.</summary>
    NotFound,

    /// <summary>The input is not valid.</summary>
    Invalid,

    /// <summary>The request is no longer in the state this needs (already decided, expired, or one is already open).</summary>
    Conflict
}

/// <summary>A refused approval action; the endpoint maps <see cref="Error"/> to a status code.</summary>
public sealed class ApprovalException(ApprovalError error, string message) : Exception(message)
{
    /// <summary>The kind of refusal.</summary>
    public ApprovalError Error { get; } = error;
}

/// <summary>The acting identity of an approval action, taken from the token.</summary>
/// <param name="Subject">The token's <c>sub</c>; null for a token without one, which can take no part.</param>
/// <param name="Name">The display name written to audit and shown to the other person.</param>
/// <param name="IsAdmin">Whether the caller holds the administrator role.</param>
public sealed record ApprovalCaller(string? Subject, string Name, bool IsAdmin);
