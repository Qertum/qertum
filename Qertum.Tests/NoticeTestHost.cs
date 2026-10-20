using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Notices;

namespace Qertum.Tests;

/// <summary>A sweeper over a real in-memory database with a fake clock and recording audit and webhooks.</summary>
internal sealed class NoticeTestHost : IAsyncDisposable
{
    public static readonly DateTimeOffset Start = new(2026, 10, 14, 12, 0, 0, TimeSpan.Zero);

    private readonly SqliteConnection _connection;
    private int _sequence;

    public CertificateRequestDbContext Db { get; }
    public FakeTimeProvider Clock { get; } = new(Start);
    public MetadataTestHost.RecordingAudit Audit { get; } = new();
    public RecordingWebhooks Webhooks { get; } = new();
    public NoticeSweeper Sweeper { get; }
    public DateTime Now => Clock.GetUtcNow().UtcDateTime;

    private NoticeTestHost(SqliteConnection connection, CertificateRequestDbContext db, NoticesOptions options, bool realWebhooks)
    {
        _connection = connection;
        Db = db;
        // The real WebhookService is internal to Qertum.Services; the tests see it through InternalsVisibleTo.
        IWebhookService webhooks = realWebhooks ? new WebhookService(db, NullLogger<WebhookService>.Instance, Clock) : Webhooks;
        Sweeper = new NoticeSweeper(db, Audit, webhooks, Options.Create(options), Clock);
    }

    public static async Task<NoticeTestHost> CreateAsync(NoticesOptions? options = null, bool realWebhooks = false)
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await db.SaveChangesAsync(ct);
        return new NoticeTestHost(connection, db, options ?? new NoticesOptions(), realWebhooks);
    }

    public Task<NoticeSweepResult> SweepAsync() => Sweeper.RunAsync(TestContext.Current.CancellationToken);

    /// <summary>An Issued certificate expiring <paramref name="validInDays"/> from now (negative = already expired).</summary>
    public async Task<CertificateRequest> IssuedAsync(string commonName, double validInDays, CertificateMetadata? metadata = null, string type = "WebServer")
    {
        var request = new CertificateRequest
        {
            CommonName = commonName, RequestedBy = "alice", Type = type, Status = CertificateRequestStatus.Issued,
            ValidFrom = Now.AddDays(-300), ValidTo = Now.AddDays(validInDays), Metadata = metadata ?? new CertificateMetadata()
        };
        Db.CertificateRequests.Add(request);
        await Db.SaveChangesAsync(TestContext.Current.CancellationToken);
        return request;
    }

    /// <summary>A renewal of <paramref name="source"/> in the given status, created <paramref name="createdHoursAgo"/> hours ago.</summary>
    public async Task<CertificateRequest> RenewalAsync(CertificateRequest source, CertificateRequestStatus status,
        double createdHoursAgo = 0, string? failureReason = null, double updatedHoursAgo = 0)
    {
        var renewal = new CertificateRequest
        {
            CommonName = $"renewal-{++_sequence}-of-{source.CommonName}", RequestedBy = source.RequestedBy, Type = "WebServer",
            Status = status, RenewedFromId = source.Id, FailureReason = failureReason,
            Metadata = source.Metadata with { },
            CreatedAtUtc = Now.AddHours(-createdHoursAgo), UpdatedAtUtc = Now.AddHours(-updatedHoursAgo)
        };
        Db.CertificateRequests.Add(renewal);
        await Db.SaveChangesAsync(TestContext.Current.CancellationToken);
        return renewal;
    }

    public async Task SetStatusAsync(CertificateRequest request, CertificateRequestStatus status)
    {
        request.Status = status;
        await Db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    public async Task<List<Notice>> NoticesAsync() =>
        await Db.Notices.AsNoTracking().OrderBy(n => n.CreatedAtUtc).ThenBy(n => n.Kind).ThenBy(n => n.Step)
            .ToListAsync(TestContext.Current.CancellationToken);

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    internal sealed class RecordingWebhooks : IWebhookService
    {
        public List<WebhookEvent> Events { get; } = [];

        /// <summary>When true, the next enqueue throws once (a webhook store that is down).</summary>
        public bool FailNext { get; set; }

        public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
        {
            if (FailNext)
            {
                FailNext = false;
                throw new InvalidOperationException("webhook store unavailable");
            }
            Events.Add(webhookEvent);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
        public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
        public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
        public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    }
}
