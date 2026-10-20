using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Qertum.Services.Webhooks;

namespace Qertum.Services;

internal sealed class WebhookService(
    CertificateRequestDbContext dbContext,
    ILogger<WebhookService> logger,
    TimeProvider? timeProvider = null) : IWebhookService
{
    // Time is read through TimeProvider so expiry and scheduling can be tested with a fake clock;
    // optional so code that constructs this directly keeps compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default)
        => await dbContext.Webhooks.OrderBy(w => w.Name).ToListAsync(cancellationToken);

    public async Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default)
        => await dbContext.Webhooks.SingleOrDefaultAsync(w => w.Id == id, cancellationToken);

    public async Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default)
    {
        webhook.Id = Guid.NewGuid();
        webhook.CreatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        webhook.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        dbContext.Webhooks.Add(webhook);
        await dbContext.SaveChangesAsync(cancellationToken);
        return webhook;
    }

    public async Task<Webhook?> UpdateAsync(WebhookId id, Webhook updated, string performedBy, CancellationToken cancellationToken = default)
    {
        var existing = await dbContext.Webhooks.SingleOrDefaultAsync(w => w.Id == id, cancellationToken);
        if (existing is null) return null;

        existing.Name = updated.Name;
        existing.Url = updated.Url;
        existing.Family = updated.Family;
        // null = keep existing secret; empty string = clear it
        if (updated.Secret is not null)
            existing.Secret = updated.Secret == string.Empty ? null : updated.Secret;
        existing.EventsJson = updated.EventsJson;
        existing.IsEnabled = updated.IsEnabled;
        existing.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;

        await dbContext.SaveChangesAsync(cancellationToken);
        return existing;
    }

    public async Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default)
    {
        var rows = await dbContext.Webhooks
            .Where(w => w.Id == id)
            .ExecuteDeleteAsync(cancellationToken);
        return rows > 0;
    }

    public async Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        try
        {
            await EnqueueCoreAsync(webhookEvent, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to enqueue webhook event {EventType} for resource {ResourceId}; delivery skipped.",
                webhookEvent.EventType, webhookEvent.ResourceId);
        }
    }

    public async Task EnqueueEventOrThrowAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        try
        {
            await EnqueueCoreAsync(webhookEvent, cancellationToken);
        }
        catch (Exception ex)
        {
            // Rows that could not be saved must not stay in the tracker: a later SaveChanges on this scope would retry them.
            foreach (var entry in dbContext.ChangeTracker.Entries<WebhookDelivery>().Where(e => e.State == EntityState.Added).ToList())
                entry.State = EntityState.Detached;
            logger.LogWarning(ex, "Failed to enqueue webhook event {EventType} for resource {ResourceId}.",
                webhookEvent.EventType, webhookEvent.ResourceId);
            throw;
        }
    }

    private async Task EnqueueCoreAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken)
    {
        if (!WellKnownWebhookEvents.TryGetFamily(webhookEvent.EventType, out var family))
        {
            logger.LogWarning("Unknown webhook event type {EventType}; nothing enqueued.", webhookEvent.EventType);
            return;
        }

        var candidates = await dbContext.Webhooks
            .Where(w => w.IsEnabled && w.Family == family)
            .ToListAsync(cancellationToken);

        var matching = candidates.Where(w => IsSubscribed(w.EventsJson, webhookEvent.EventType)).ToList();
        if (matching.Count == 0) return;

        // KeyAccess deliberately discloses less: the certificate's id and common name stay in the
        // audit log rather than reaching an external endpoint. Suppressing here, at the single
        // choke point, means no call site can leak them by passing them in.
        var suppressIdentity = family == WebhookEventFamily.KeyAccess;
        var resourceId = suppressIdentity ? null : webhookEvent.ResourceId;
        var resourceName = suppressIdentity ? null : webhookEvent.ResourceName;

        var timestamp = _clock.GetUtcNow().UtcDateTime;

        // Only allowlisted family fields survive; anything else the caller passed is dropped.
        var data = new Dictionary<string, string?>(StringComparer.Ordinal);
        if (webhookEvent.Fields is not null)
        {
            foreach (var (key, value) in webhookEvent.Fields)
            {
                if (WebhookEventFields.For(family).Contains(key))
                    data[key] = value;
                else
                    logger.LogWarning("Dropping field {Field}: not carried by the {Family} family.", key, family);
            }
        }

        var payload = JsonSerializer.Serialize(new
        {
            @event = webhookEvent.EventType,
            family = family.ToString(),
            timestamp,
            performedBy = webhookEvent.PerformedBy,
            resourceId,
            resourceName,
            detail = webhookEvent.Detail,
            data
        }, JsonWeb);

        // The same values back the URL placeholders, so body and URL cannot disagree.
        var placeholders = new Dictionary<string, string?>(data, StringComparer.Ordinal)
        {
            ["event"] = webhookEvent.EventType,
            ["family"] = family.ToString(),
            ["timestamp"] = timestamp.ToString("O"),
            ["performedBy"] = webhookEvent.PerformedBy,
            ["resourceId"] = resourceId?.ToString(),
            ["resourceName"] = resourceName
        };

        foreach (var w in matching)
        {
            dbContext.WebhookDeliveries.Add(new WebhookDelivery
            {
                Id = Guid.NewGuid(),
                WebhookId = w.Id,
                EventType = webhookEvent.EventType,
                ResourceId = resourceId,
                ResourceName = resourceName,
                Payload = payload,
                ResolvedUrl = WebhookUrlTemplate.Resolve(w.Url, placeholders),
                Status = "Pending",
                AttemptCount = 0,
                NextAttemptAfterUtc = timestamp,
                CreatedAtUtc = timestamp
            });
        }

        await dbContext.SaveChangesAsync(cancellationToken);
    }

    /// <summary>
    /// Whether this webhook's narrowing subset admits the event. An empty array means the whole family,
    /// which is the default for a new webhook.
    /// </summary>
    private static bool IsSubscribed(string eventsJson, string eventType)
    {
        try
        {
            var events = JsonSerializer.Deserialize<string[]>(eventsJson, JsonWeb);
            return events is null or { Length: 0 } ||
                   events.Contains(eventType, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            // A malformed subset is treated as the whole family rather than silently delivering nothing.
            return true;
        }
    }
}
