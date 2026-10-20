using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>What a <see cref="Notice"/> is about.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NoticeKind
{
    /// <summary>An issued certificate is within one of the configured day thresholds of its expiry and has no renewal.</summary>
    Expiring,

    /// <summary>A renewal has been Pending approval longer than the attention age.</summary>
    RenewalStalled,

    /// <summary>A renewal was rejected by the pipeline with a failure reason.</summary>
    RenewalFailed
}

/// <summary>Whether the situation a <see cref="Notice"/> reports still holds.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum NoticeStatus
{
    /// <summary>The situation still holds.</summary>
    Open,

    /// <summary>The situation ended; the sweeper closed the notice.</summary>
    Resolved
}

/// <summary>
/// One situation that needs a person: stored so it is raised once per step, delivered at least once as a
/// webhook, and listed in the Web UI until it resolves itself.
/// </summary>
public sealed class Notice
{
    /// <summary>Notice identifier.</summary>
    public NoticeId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>The request the notice is about: the certificate for <see cref="NoticeKind.Expiring"/>, the renewal otherwise.</summary>
    public CertificateRequestId RequestId { get; set; }

    /// <summary>The certificate being renewed, for the renewal kinds; null for <see cref="NoticeKind.Expiring"/>.</summary>
    public CertificateRequestId? SourceRequestId { get; set; }

    /// <summary>What the notice is about, stored as its name.</summary>
    public NoticeKind Kind { get; set; }

    /// <summary>For <see cref="NoticeKind.Expiring"/> the day threshold crossed; for the renewal kinds the escalation level (1 or 2).</summary>
    public int Step { get; set; }

    /// <summary>Open until the situation ends, stored as its name.</summary>
    public NoticeStatus Status { get; set; } = NoticeStatus.Open;

    /// <summary>When the sweeper raised it (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>When the sweeper closed it (UTC).</summary>
    public DateTime? ResolvedAtUtc { get; set; }

    /// <summary>When its webhook was queued (UTC); null until then, which is how a lost delivery is retried.</summary>
    public DateTime? WebhookQueuedAtUtc { get; set; }
}

/// <summary>A notice as the API lists it, with the certificate's name and the contact from its metadata.</summary>
public sealed class NoticeItem
{
    /// <summary>Notice identifier.</summary>
    public NoticeId Id { get; init; }

    /// <summary>The request the notice is about.</summary>
    public CertificateRequestId RequestId { get; init; }

    /// <summary>The certificate being renewed, for the renewal kinds.</summary>
    public CertificateRequestId? SourceRequestId { get; init; }

    /// <summary>What the notice is about.</summary>
    public NoticeKind Kind { get; init; }

    /// <summary>Day threshold (expiring) or escalation level (renewal kinds).</summary>
    public int Step { get; init; }

    /// <summary>Whether the situation still holds.</summary>
    public NoticeStatus Status { get; init; }

    /// <summary>Common name of <see cref="RequestId"/>, or null when that request no longer exists.</summary>
    public string? CommonName { get; init; }

    /// <summary>When the notice was raised (UTC).</summary>
    public DateTime CreatedAtUtc { get; init; }

    /// <summary>When it resolved (UTC).</summary>
    public DateTime? ResolvedAtUtc { get; init; }

    /// <summary>Owner team from the certificate metadata; null reads as Unknown.</summary>
    public string? OwnerTeam { get; init; }

    /// <summary>Contact email from the certificate metadata; null reads as Unknown. Not an authorization-bearing identity.</summary>
    public string? ContactEmail { get; init; }
}

/// <summary>One-line wording for a notice, shared by the API, the CLI and the Web UI.</summary>
public static class NoticeDescriptions
{
    /// <summary>What the notice says, from its kind and step.</summary>
    public static string Describe(NoticeKind kind, int step) => kind switch
    {
        NoticeKind.Expiring => $"expires within {step} {(step == 1 ? "day" : "days")}",
        NoticeKind.RenewalStalled => $"renewal waiting for approval (level {step})",
        NoticeKind.RenewalFailed => $"renewal failed (level {step})",
        _ => kind.ToString()
    };
}
