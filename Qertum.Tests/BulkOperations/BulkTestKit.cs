using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.BulkOperations;

namespace Qertum.Tests.BulkOperations;

internal sealed class RecordingAudit : IAuditLogService
{
    public List<(string Action, string PerformedBy, string? Detail)> Entries { get; } = [];

    public Task LogAsync(string action, string performedBy, Guid? resourceId = null, string? resourceName = null,
        string? detail = null, CancellationToken cancellationToken = default)
    {
        Entries.Add((action, performedBy, detail));
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

internal sealed class RecordingWebhooks : IWebhookService
{
    public List<WebhookEvent> Events { get; } = [];
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default)
    {
        Events.Add(webhookEvent);
        return Task.CompletedTask;
    }
}

/// <summary>Records enqueued jobs; returns null (key already held) for a second job under the same key.</summary>
internal sealed class RecordingJobQueue : IBackgroundJobQueue
{
    public List<BackgroundJob> Jobs { get; } = [];

    public Task<BackgroundJob?> EnqueueAsync(string jobType, string? concurrencyKey, string requestedBy, string? reason,
        string? payloadJson = null, CancellationToken cancellationToken = default)
    {
        if (concurrencyKey is not null && Jobs.Any(j => j.ConcurrencyKey == concurrencyKey))
            return Task.FromResult<BackgroundJob?>(null);
        var job = new BackgroundJob { JobType = jobType, ConcurrencyKey = concurrencyKey, RequestedBy = requestedBy, Reason = reason, PayloadJson = payloadJson };
        Jobs.Add(job);
        return Task.FromResult<BackgroundJob?>(job);
    }

    public Task<BackgroundJob?> ClaimNextAsync(IReadOnlyCollection<string> handledJobTypes, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task CompleteAsync(BackgroundJob job, string? result, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task ScheduleRetryAsync(BackgroundJob job, string error, DateTime nextAttemptAfterUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task FailAsync(BackgroundJob job, string error, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<int> RecoverStuckAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<int> RecoverStaleAsync(DateTime claimedBeforeUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<int> DeleteFinishedBeforeAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

/// <summary>One in-memory SQLite database plus fakes, shared by the bulk service and runner tests.</summary>
internal sealed class BulkScope : IAsyncDisposable
{
    public static readonly BulkActor Operator = new("sub-op", "operator", IsAdmin: false, HoldsCaPermission: false);

    private readonly SqliteConnection _connection;
    private readonly List<CertificateRequestDbContext> _contexts = [];

    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 10, 8, 12, 0, 0, TimeSpan.Zero));
    public RecordingAudit Audit { get; } = new();
    public RecordingWebhooks Webhooks { get; } = new();
    public RecordingJobQueue Jobs { get; } = new();

    private BulkScope(SqliteConnection connection) => _connection = connection;

    public static async Task<BulkScope> CreateAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(TestContext.Current.CancellationToken);
        var scope = new BulkScope(connection);
        await using var db = scope.NewDb();
        await db.Database.EnsureCreatedAsync(TestContext.Current.CancellationToken);
        return scope;
    }

    public CertificateRequestDbContext NewDb()
    {
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(_connection).Options,
            new EphemeralDataProtectionProvider());
        _contexts.Add(db);
        return db;
    }

    public BulkOperationService CreateService(BulkOperationsOptions? options = null) =>
        new(NewDb(), Options.Create(options ?? new BulkOperationsOptions()), Audit, Jobs, Clock);

    /// <summary>Adds an Issued request with the given facts.</summary>
    public async Task<CertificateRequestId> AddIssuedAsync(string commonName, string type = "WebServer",
        IssuerId? issuerId = null, string? ownerSubject = null, DateTime? validTo = null, string? csrPem = null,
        CertificateRequestStatus status = CertificateRequestStatus.Issued)
    {
        await using var db = NewDb();
        var request = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = commonName,
            RequestedBy = "seed",
            RequestedBySubject = ownerSubject,
            Type = type,
            IssuerId = issuerId,
            Status = status,
            ValidFrom = Clock.GetUtcNow().UtcDateTime.AddDays(-30),
            ValidTo = validTo ?? Clock.GetUtcNow().UtcDateTime.AddDays(300),
            CsrPem = csrPem,
            CreatedAtUtc = Clock.GetUtcNow().UtcDateTime,
            UpdatedAtUtc = Clock.GetUtcNow().UtcDateTime
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        return request.Id;
    }

    /// <summary>Adds a renewal child of <paramref name="sourceId"/> in the given status.</summary>
    public async Task AddRenewalOfAsync(CertificateRequestId sourceId, CertificateRequestStatus status)
    {
        await using var db = NewDb();
        db.CertificateRequests.Add(new CertificateRequest
        {
            Id = Guid.NewGuid(), CommonName = "renewal", RequestedBy = "seed", Status = status,
            RenewedFromId = sourceId, CreatedAtUtc = Clock.GetUtcNow().UtcDateTime, UpdatedAtUtc = Clock.GetUtcNow().UtcDateTime
        });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    public async Task AddCaTemplateAsync(string typeKey)
    {
        await using var db = NewDb();
        // EnsureCreated already seeds the built-in templates (SubordinateCA is CA-capable); only add what is missing.
        if (await db.CertificateTemplates.AnyAsync(t => t.TypeKey == typeKey, TestContext.Current.CancellationToken)) return;
        db.CertificateTemplates.Add(new CertificateTemplate { Name = typeKey, TypeKey = typeKey, KeyUsagesJson = "[\"KeyCertSign\"]" });
        await db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var db in _contexts) await db.DisposeAsync();
        await _connection.DisposeAsync();
    }
}
