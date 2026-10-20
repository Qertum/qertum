using System.Security.Cryptography;
using System.Text;
using Qertum.Services;
using Qertum.Services.Webhooks;
using Microsoft.EntityFrameworkCore;

namespace Qertum.QueueConsumer;

internal sealed class WebhookDeliveryService(
    IServiceScopeFactory serviceScopeFactory,
    ILogger<WebhookDeliveryService> logger,
    Microsoft.Extensions.Options.IOptions<WebhookDeliveryOptions> options,
    HttpClient httpClient,
    OperationsMetrics? metrics = null,
    TimeProvider? timeProvider = null) : BackgroundService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private const int MaxRetries = 5;
    private const int BatchSize = 50;

    private readonly TimeSpan _pollInterval = TimeSpan.FromSeconds(options.Value.DeliveryPollIntervalSeconds);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessPendingDeliveriesAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(ex, "Webhook delivery scan failed; will retry in {Interval}.", _pollInterval);
            }

            await Task.Delay(_pollInterval, stoppingToken);
        }
    }

    private async Task ProcessPendingDeliveriesAsync(CancellationToken cancellationToken)
    {
        await using var scope = serviceScopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var policyService = scope.ServiceProvider.GetRequiredService<IWebhookDestinationPolicyService>();
        await ProcessPendingAsync(db, policyService, cancellationToken);
    }

    private async Task ProcessPendingAsync(CertificateRequestDbContext db,
        IWebhookDestinationPolicyService policyService, CancellationToken cancellationToken)
    {
        var pending = await db.WebhookDeliveries
            .Where(d => d.Status == "Pending" && d.NextAttemptAfterUtc <= _clock.GetUtcNow().UtcDateTime)
            .OrderBy(d => d.CreatedAtUtc)
            .Take(BatchSize)
            .ToListAsync(cancellationToken);

        if (pending.Count == 0) return;

        // Load all referenced webhooks in one query
        var webhookIds = pending.Select(d => d.WebhookId).Distinct().ToList();
        var webhooks = await db.Webhooks
            .Where(w => webhookIds.Contains(w.Id))
            .ToDictionaryAsync(w => w.Id, cancellationToken);

        foreach (var delivery in pending)
        {
            if (!webhooks.TryGetValue(delivery.WebhookId, out var webhook) || !webhook.IsEnabled)
            {
                delivery.Status = "Failed";
                delivery.LastErrorMessage = webhook is null ? "Webhook not found." : "Webhook is disabled.";
                RecordDelivery("failed");
                continue;
            }

            await DeliverAsync(delivery, webhook, policyService, cancellationToken);
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    private async Task DeliverAsync(WebhookDelivery delivery, Webhook webhook,
        IWebhookDestinationPolicyService policyService, CancellationToken cancellationToken)
    {
        // Rows written before webhook event families shipped have no resolved URL.
        var targetUrl = string.IsNullOrWhiteSpace(delivery.ResolvedUrl) ? webhook.Url : delivery.ResolvedUrl;

        try
        {
            var policy = await policyService.GetEffectiveAsync(cancellationToken);
            string? reason = null;
            if (targetUrl.Length > 4000 || targetUrl.Contains('{') || targetUrl.Contains('}') ||
                !policyService.CanSaveUrl(policy, targetUrl, out reason))
                throw new HttpRequestException(reason ?? "Webhook destination is invalid or not allowed by policy.");

            var content = new StringContent(delivery.Payload, Encoding.UTF8, "application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post, targetUrl) { Content = content };
            request.Options.Set(WebhookDestinationHttpHandler.PolicyKey, policy);
            request.Headers.Add("X-Webhook-Event", delivery.EventType);
            request.Headers.Add("X-Webhook-Delivery", delivery.Id.ToString());

            if (!string.IsNullOrEmpty(webhook.Secret))
            {
                var sig = ComputeHmacSha256(webhook.Secret, delivery.Payload);
                request.Headers.Add("X-Webhook-Signature", $"sha256={sig}");
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(10));

            using var response = await httpClient.SendAsync(request, cts.Token);

            if (response.IsSuccessStatusCode)
            {
                delivery.Status = "Delivered";
                delivery.AttemptCount++;
                RecordDelivery("delivered");
                logger.LogInformation("Webhook {DeliveryId} delivered to {Url} ({Event}).", delivery.Id, targetUrl, delivery.EventType);
                return;
            }

            delivery.LastErrorMessage = $"HTTP {(int)response.StatusCode}";
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            delivery.LastErrorMessage = ex.Message;
        }

        delivery.AttemptCount++;

        if (delivery.AttemptCount >= MaxRetries)
        {
            delivery.Status = "Failed";
            RecordDelivery("failed");
            logger.LogWarning("Webhook {DeliveryId} permanently failed after {Attempts} attempts ({Url}): {Error}",
                delivery.Id, delivery.AttemptCount, targetUrl, delivery.LastErrorMessage);
        }
        else
        {
            // Exponential backoff capped at 24 hours
            var delay = TimeSpan.FromSeconds(Math.Min(Math.Pow(2, delivery.AttemptCount) * 30, 86400));
            delivery.NextAttemptAfterUtc = _clock.GetUtcNow().UtcDateTime.Add(delay);
            RecordDelivery("retry");
            logger.LogWarning("Webhook {DeliveryId} attempt {Attempt} failed ({Url}): {Error}. Next retry at {Next:u}.",
                delivery.Id, delivery.AttemptCount, targetUrl, delivery.LastErrorMessage, delivery.NextAttemptAfterUtc);
        }
    }

    private void RecordDelivery(string outcome) =>
        metrics?.WebhookDeliveries.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    private static string ComputeHmacSha256(string secret, string payload)
    {
        var key = Encoding.UTF8.GetBytes(secret);
        var data = Encoding.UTF8.GetBytes(payload);
        var hash = HMACSHA256.HashData(key, data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
