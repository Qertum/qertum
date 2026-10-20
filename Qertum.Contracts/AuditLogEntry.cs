namespace Qertum.Services;

/// <summary>
/// One immutable audit record written on every certificate lifecycle transition or CA settings change.
/// </summary>
public sealed class AuditLogEntry
{
    /// <summary>Unique identifier for the audit log entry.</summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Human-readable action name: Created, Approved, Rejected, Issued, Revoked, Renewed, SettingsUpdated.
    /// </summary>
    public string Action { get; init; } = string.Empty;

    /// <summary>
    /// The certificate request or settings resource the action was performed on (null for global actions).
    /// </summary>
    public Guid? ResourceId { get; init; }

    /// <summary>
    /// The CommonName of the certificate at the time of the action (snapshot for readability).
    /// </summary>
    public string? ResourceName { get; init; }

    /// <summary>
    /// The 'sub' claim from the JWT of the user who triggered this action.
    /// </summary>
    public string PerformedBy { get; init; } = string.Empty;

    /// <summary>
    /// UTC timestamp of the action.
    /// </summary>
    public DateTime OccurredAtUtc { get; init; }

    /// <summary>
    /// Optional free-text detail (e.g. revocation reason, renewal source ID).
    /// </summary>
    public string? Detail { get; init; }

    /// <summary>
    /// W3C trace ID of the request that triggered this action, for correlation with distributed traces.
    /// Null for entries written outside of an active trace (e.g. background service actions).
    /// </summary>
    public string? TraceId { get; init; }
}
