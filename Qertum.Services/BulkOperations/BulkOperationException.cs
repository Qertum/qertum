namespace Qertum.Services.BulkOperations;

/// <summary>A bulk operation request that cannot be honoured; carries the HTTP status the API answers with.</summary>
/// <param name="statusCode">422 refused input, 404 unknown, 409 wrong state or count, 410 expired.</param>
/// <param name="detail">Reason for the problem details body.</param>
public sealed class BulkOperationException(int statusCode, string detail) : Exception(detail)
{
    /// <summary>The HTTP status to answer with.</summary>
    public int StatusCode { get; } = statusCode;

    /// <summary>The reason, for the problem <c>detail</c>.</summary>
    public string Detail { get; } = detail;
}

/// <summary>The identity performing a bulk call, as the API resolved it.</summary>
/// <param name="Subject">Stable subject; null for a legacy identity without one.</param>
/// <param name="Name">Display name.</param>
/// <param name="IsAdmin">Holds the admin role.</param>
/// <param name="HoldsCaPermission">Holds <c>certificates.ca</c>.</param>
public sealed record BulkActor(string? Subject, string Name, bool IsAdmin, bool HoldsCaPermission);
