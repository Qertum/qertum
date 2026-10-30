using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

internal sealed class NullAuditLog : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default) => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

internal sealed class NullWebhooks : IWebhookService
{
    /// <summary>Every event enqueued, so a test can read what would have been sent.</summary>
    public List<WebhookEvent> Events { get; } = [];

    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        lock (Events) Events.Add(webhookEvent);
        return Task.CompletedTask;
    }
}

internal static class IssuanceSignerFactory
{
    /// <summary>An <see cref="IssuanceSigner"/> over the kit's files and <paramref name="db"/>, auditing and webhooks discarded.</summary>
    public static IssuanceSigner Create(IssuerTestKit kit, IIssuerRegistry registry, CertificateRequestDbContext db,
        ICertificateTemplateService templates) =>
        new(registry, templates, kit.Legacy, kit.Storage, kit.DataProtection, NullLoggerFactory.Instance,
            new IssuerLifecycleService(db, registry, kit.Storage, new NullAuditLog(), new NullWebhooks()), db);
}
