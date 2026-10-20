using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Where a timeline entry comes from.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TimelineEntryKind
{
    /// <summary>A copy of an audit event.</summary>
    Audit,

    /// <summary>An operational event, such as a refused re-enrollment.</summary>
    Diagnostic,

    /// <summary>A milestone read from the request's own columns, for history with no event.</summary>
    Record,

    /// <summary>A webhook delivery for this request.</summary>
    WebhookDelivery,

    /// <summary>A link to the request this one renews, or to one renewing it.</summary>
    Renewal,

    /// <summary>A note written by a person (see <see cref="CertificateNote"/>); <see cref="TimelineEntry.Detail"/> is its text.</summary>
    Note
}

/// <summary>A part of a timeline the caller may not see.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TimelineSection
{
    /// <summary>Webhook deliveries; needs <c>settings.edit</c>.</summary>
    WebhookDeliveries,

    /// <summary>Private-key and PKCS#12 exports; owner or administrator only.</summary>
    KeyExports,

    /// <summary>Diagnostic events; needs <c>settings.edit</c>.</summary>
    Diagnostics
}

/// <summary>Whether the timeline can be complete.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TimelineCompleteness
{
    /// <summary>The request is newer than the first recorded event.</summary>
    Full,

    /// <summary>The request predates event recording; older steps come from its own columns only.</summary>
    PartialBeforeUpgrade
}

/// <summary>One step in a certificate's history.</summary>
public sealed class TimelineEntry
{
    /// <summary>When it happened (UTC).</summary>
    public DateTime OccurredAtUtc { get; init; }

    /// <summary>Where the entry comes from.</summary>
    public TimelineEntryKind Kind { get; init; }

    /// <summary>What happened, e.g. <c>Approved</c>, <c>RenewedFrom</c>, or a webhook event name.</summary>
    public string Action { get; init; } = string.Empty;

    /// <summary>A classification: a delivery status, or a diagnostic category.</summary>
    public string? Category { get; init; }

    /// <summary>Who or what did it.</summary>
    public string? PerformedBy { get; init; }

    /// <summary>Free-text detail recorded with the event.</summary>
    public string? Detail { get; init; }

    /// <summary>A fixed plain-language next step, when there is one.</summary>
    public string? Hint { get; init; }

    /// <summary>For renewal entries, the other request.</summary>
    public Guid? RelatedRequestId { get; init; }

    /// <summary>The note's id, for <see cref="TimelineEntryKind.Note"/> entries.</summary>
    public NoteId? NoteId { get; init; }

    /// <summary>True when a note was edited after it was written.</summary>
    public bool Edited { get; init; }

    /// <summary>When a note was last edited (UTC); null for other entries.</summary>
    public DateTime? UpdatedAtUtc { get; init; }

    /// <summary>True when the caller wrote the note; only the author edits or deletes it.</summary>
    public bool Mine { get; init; }
}

/// <summary>The facts shown for a certificate in the timeline header and the renewal comparison.</summary>
public sealed class TimelineCertificateSummary
{
    /// <summary>Request id.</summary>
    public Guid Id { get; init; }

    /// <summary>Common name.</summary>
    public string CommonName { get; init; } = string.Empty;

    /// <summary>Current status.</summary>
    public CertificateRequestStatus Status { get; init; }

    /// <summary>Serial number, once issued.</summary>
    public string? SerialNumber { get; init; }

    /// <summary>Start of validity, once issued.</summary>
    public DateTime? ValidFrom { get; init; }

    /// <summary>End of validity, once issued.</summary>
    public DateTime? ValidTo { get; init; }

    /// <summary>How many notes the request holds; filled for the related requests of a timeline.</summary>
    public int NoteCount { get; init; }
}

/// <summary>A section the caller may not see, and how many entries it holds.</summary>
public sealed class WithheldTimelineSection
{
    /// <summary>The section.</summary>
    public TimelineSection Section { get; init; }

    /// <summary>Entries withheld; zero still means the section exists and is not visible.</summary>
    public int Count { get; init; }
}

/// <summary>The history of one certificate request, as far as the caller may see it.</summary>
public sealed class CertificateTimelineResponse
{
    /// <summary>The request this timeline is for.</summary>
    public TimelineCertificateSummary Subject { get; init; } = new();

    /// <summary>Entries, oldest first.</summary>
    public List<TimelineEntry> Entries { get; init; } = [];

    /// <summary>The requests that renewal entries point at.</summary>
    public List<TimelineCertificateSummary> Related { get; init; } = [];

    /// <summary>Every section the caller may not see, listed even when empty.</summary>
    public List<WithheldTimelineSection> Withheld { get; init; } = [];

    /// <summary>Whether older history can be missing.</summary>
    public TimelineCompleteness Completeness { get; init; }
}
