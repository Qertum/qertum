using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>An in-memory service stack for metadata tests: the real service and database, a recording audit log.</summary>
internal sealed class MetadataTestHost : IAsyncDisposable
{
    private readonly SqliteConnection _connection;

    public CertificateRequestDbContext Db { get; }
    public CertificateRequestService Service { get; }
    public RecordingAudit Audit { get; }

    private MetadataTestHost(SqliteConnection connection, CertificateRequestDbContext db, RecordingAudit audit)
    {
        _connection = connection;
        Db = db;
        Audit = audit;
        Service = new CertificateRequestService(db, audit, new NoWebhooks(),
            new Qertum.Services.Policies.IssuancePolicyService(db, new Qertum.Services.Policies.IssuancePolicyEvaluator()));
    }

    public static async Task<MetadataTestHost> CreateAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options;
        var db = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        // The CA default is PQC stage Enforce; these tests use RSA, so they start from Off.
        db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await db.SaveChangesAsync(ct);
        return new MetadataTestHost(connection, db, new RecordingAudit());
    }

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    internal sealed class RecordingAudit : IAuditLogService
    {
        public List<(string Action, string? Detail)> Entries { get; } = [];

        public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        {
            Entries.Add((action, detail));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
    }

    internal sealed class NoWebhooks : IWebhookService
    {
        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }
}
