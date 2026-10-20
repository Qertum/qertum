namespace Qertum.Services;

/// <summary>A webhook subscription that receives HTTP POST notifications for certificate lifecycle events.</summary>
public sealed class Webhook
{
    /// <summary>Unique identifier for this webhook.</summary>
    public WebhookId Id { get; set; }

    /// <summary>Human-readable display name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Target URL that receives HTTP POST deliveries.</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>
    /// The single event family this webhook receives. <see cref="EventsJson"/> narrows it; an empty
    /// array means every event in the family.
    /// </summary>
    public WebhookEventFamily Family { get; set; } = WebhookEventFamily.CertificateRequest;

    /// <summary>
    /// Optional HMAC-SHA256 signing secret. When set, deliveries include an
    /// <c>X-Webhook-Signature: sha256=&lt;hex&gt;</c> header. Stored encrypted at rest.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>
    /// JSON array naming the subset of <see cref="Family"/> to deliver (e.g. <c>["Issued","Revoked"]</c>).
    /// An empty array — the default — means every event in the family.
    /// </summary>
    public string EventsJson { get; set; } = "[]";

    /// <summary>When <see langword="false"/>, no deliveries are attempted for this webhook.</summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>UTC timestamp when the webhook was created.</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>UTC timestamp of the last update.</summary>
    public DateTime UpdatedAtUtc { get; set; }
}
