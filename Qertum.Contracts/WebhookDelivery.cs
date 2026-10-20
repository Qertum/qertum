namespace Qertum.Services;

/// <summary>A pending or completed webhook delivery attempt (outbox entry).</summary>
public sealed class WebhookDelivery
{
    /// <summary>Unique identifier for this delivery record.</summary>
    public Guid Id { get; init; }

    /// <summary>The webhook subscription this delivery belongs to.</summary>
    public WebhookId WebhookId { get; init; }

    /// <summary>Event type string (e.g. <c>"Issued"</c>, <c>"Approved"</c>).</summary>
    public string EventType { get; init; } = string.Empty;

    /// <summary>ID of the certificate request that triggered the event.</summary>
    public Guid? ResourceId { get; init; }

    /// <summary>Common name of the resource at the time of the event.</summary>
    public string? ResourceName { get; init; }

    /// <summary>Pre-serialised JSON body to POST to the webhook URL.</summary>
    public string Payload { get; init; } = string.Empty;

    /// <summary>
    /// The target URL with its <c>{placeholder}</c> tokens already substituted, recorded at enqueue
    /// time so the row states exactly what was called and a retry is unaffected by later edits to
    /// the webhook. Null on rows written before webhook event families shipped; delivery then falls
    /// back to <see cref="Webhook.Url"/>.
    /// </summary>
    public string? ResolvedUrl { get; init; }

    /// <summary>Delivery status: <c>Pending</c>, <c>Delivered</c>, or <c>Failed</c>.</summary>
    public string Status { get; set; } = "Pending";

    /// <summary>Number of delivery attempts made so far.</summary>
    public int AttemptCount { get; set; }

    /// <summary>Earliest UTC time at which the next delivery attempt should be made.</summary>
    public DateTime NextAttemptAfterUtc { get; set; }

    /// <summary>Error message from the most recent failed attempt.</summary>
    public string? LastErrorMessage { get; set; }

    /// <summary>UTC timestamp when the outbox entry was created.</summary>
    public DateTime CreatedAtUtc { get; init; }
}
