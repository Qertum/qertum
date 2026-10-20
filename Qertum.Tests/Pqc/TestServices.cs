using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Pqc;

internal static class TestServices
{
    /// <summary>A request service over <paramref name="db"/> with no-op audit and webhook doubles.</summary>
    internal static CertificateRequestService CreateRequestService(CertificateRequestDbContext db, TimeProvider? clock = null) =>
        new(db, new NoAudit(), new NoWebhooks(), new IssuancePolicyService(db, new IssuancePolicyEvaluator()),
            timeProvider: clock);

    /// <summary>Sets the CA default stage directly, the way an admin endpoint eventually will.</summary>
    internal static async Task SetStageAsync(CertificateRequestDbContext db, PqcStage stage)
    {
        var row = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1);
        if (row is null) db.Settings.Add(new CaSettings { Id = 1, PqcStage = stage });
        else row.PqcStage = stage;
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    private sealed class NoWebhooks : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class NoAudit : IAuditLogService
    {
        public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
            => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }
}
