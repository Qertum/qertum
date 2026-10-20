namespace Qertum.Services;

public interface IWebhookService
{
    Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default);

    Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default);

    Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default);

    Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes <see cref="WebhookDelivery"/> rows for every enabled webhook whose family owns
    /// <paramref name="webhookEvent"/>'s type and whose event subset admits it. The family is derived
    /// from the event name, never supplied by the caller. Non-fatal: errors are logged as warnings and
    /// swallowed so the calling mutation is never rolled back.
    /// </summary>
    Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Like <see cref="EnqueueEventAsync"/>, but a failure to write the delivery rows is thrown (after the half-written
    /// rows are dropped from the change tracker) instead of swallowed. For callers that must know whether the event was
    /// queued, such as the notice sweeper, which retries a delivery that never reached the queue. Having no subscriber
    /// is not a failure. The default only forwards, for implementations that cannot fail.
    /// </summary>
    Task EnqueueEventOrThrowAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) =>
        EnqueueEventAsync(webhookEvent, cancellationToken);
}
