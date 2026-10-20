namespace Qertum.Services;

/// <summary>
/// One occurrence to enqueue for delivery. The family is derived from <paramref name="EventType"/> by
/// <c>WellKnownWebhookEvents.FamilyOf</c> and is never supplied by the caller, so an event cannot be
/// filed under the wrong family.
/// </summary>
/// <param name="EventType">An event name from <c>WellKnownWebhookEvents</c>.</param>
/// <param name="ResourceId">The affected resource's id, where it has one.</param>
/// <param name="ResourceName">A display name for the resource (common name, template name, policy name).</param>
/// <param name="Detail">Optional free-text note, carried through to the body's <c>detail</c> field.</param>
/// <param name="PerformedBy">The acting identity, as the audit log records it.</param>
/// <param name="Fields">
/// Family-specific values, keyed by the names in <see cref="WebhookEventFields.For"/>. Keys outside
/// that allowlist are dropped when the delivery is built.
/// </param>
public sealed record WebhookEvent(
    string EventType,
    Guid? ResourceId = null,
    string? ResourceName = null,
    string? Detail = null,
    string? PerformedBy = null,
    IReadOnlyDictionary<string, string?>? Fields = null);
