namespace Qertum.Services;

/// <summary>Where a two-person approval stands. Stored and serialized as its name.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter))]
public enum ApprovalStatus
{
    /// <summary>Waiting for a second administrator.</summary>
    Pending,

    /// <summary>Approved; the requester may perform the operation once before <see cref="ApprovalRequest.GrantExpiresAtUtc"/>.</summary>
    Approved,

    /// <summary>Refused by an administrator.</summary>
    Denied,

    /// <summary>The grant has been used.</summary>
    Used,

    /// <summary>Not decided in time, or approved and not used in time.</summary>
    Expired
}

/// <summary>
/// One request for a second person's agreement to a sensitive operation, and the one-use grant that follows.
/// The stored <see cref="Status"/> is not trusted for expiry: read it through the approval service's effective status.
/// </summary>
public sealed class ApprovalRequest
{
    /// <summary>Approval identifier.</summary>
    public ApprovalRequestId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>Operation key, one of the values in the approval route table (for example <c>bulk-revoke</c>).</summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>The thing the operation acts on (a certificate request, issuer, policy or bulk operation id); null for creating an intermediate.</summary>
    public string? TargetId { get; set; }

    /// <summary>What the requester says they will do. Plain text, never written to audit text or webhooks.</summary>
    public string? Note { get; set; }

    /// <summary>The requester's <c>sub</c>; a grant can be used only by this subject.</summary>
    public string RequestedBySubject { get; set; } = string.Empty;

    /// <summary>The requester's display name.</summary>
    public string RequestedByName { get; set; } = string.Empty;

    /// <summary>When the request was filed (UTC).</summary>
    public DateTime RequestedAtUtc { get; set; }

    /// <summary>Stored status; see the type remarks.</summary>
    public ApprovalStatus Status { get; set; } = ApprovalStatus.Pending;

    /// <summary>The deciding administrator's <c>sub</c>.</summary>
    public string? DecidedBySubject { get; set; }

    /// <summary>The deciding administrator's display name.</summary>
    public string? DecidedByName { get; set; }

    /// <summary>When it was decided (UTC).</summary>
    public DateTime? DecidedAtUtc { get; set; }

    /// <summary>The decider's note.</summary>
    public string? DecisionNote { get; set; }

    /// <summary>End of the window in which an approved grant can be used (UTC).</summary>
    public DateTime? GrantExpiresAtUtc { get; set; }

    /// <summary>When the grant was used (UTC).</summary>
    public DateTime? UsedAtUtc { get; set; }
}
