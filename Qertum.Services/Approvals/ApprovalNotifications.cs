namespace Qertum.Services.Approvals;

/// <summary>The audit entry and webhook event of an approval step. Neither ever carries a note.</summary>
internal static class ApprovalNotifications
{
    /// <summary>Writes the audit entry and enqueues the webhook for <paramref name="action"/> (also the event name).</summary>
    public static async Task PublishAsync(
        IAuditLogService auditLog, IWebhookService webhooks, string action, string performedBy,
        ApprovalRequest request, ApprovalStatus status, CancellationToken cancellationToken)
    {
        var detail = $"{request.Operation} target={request.TargetId ?? "-"} requestedBy={request.RequestedByName}"
            + (request.DecidedByName is null ? "" : $" decidedBy={request.DecidedByName}");
        await auditLog.LogAsync(action, performedBy, request.Id.Value, request.Operation, detail, cancellationToken);
        await webhooks.EnqueueEventAsync(new WebhookEvent(
            action, request.Id.Value, request.Operation, PerformedBy: performedBy,
            Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["approvalId"] = request.Id.ToString(),
                ["operation"] = request.Operation,
                ["targetId"] = request.TargetId,
                ["requestedBy"] = request.RequestedByName,
                ["decidedBy"] = request.DecidedByName,
                ["status"] = status.ToString(),
                ["grantExpiresAtUtc"] = request.GrantExpiresAtUtc?.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            }), cancellationToken);
    }
}
