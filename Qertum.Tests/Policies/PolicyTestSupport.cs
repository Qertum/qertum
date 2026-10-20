using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>In-memory SQLite database with the full schema (including seeded templates).</summary>
internal sealed partial class PolicyTestDb : IAsyncDisposable
{
    private PolicyTestDb(SqliteConnection connection, CertificateRequestDbContext db)
    {
        Connection = connection;
        Db = db;
    }

    public SqliteConnection Connection { get; }

    public CertificateRequestDbContext Db { get; }

    public RecordingPolicyAuditLog Audit { get; } = new();

    /// <summary>
    /// Seeds a settings row at PQC stage Off unless <paramref name="seedSettings"/> is false: the CA
    /// default is Enforce, and these tests are about policy, not about classical keys being refused.
    /// </summary>
    public static async Task<PolicyTestDb> CreateAsync(CancellationToken ct, bool seedSettings = true)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        if (seedSettings)
        {
            db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
            await db.SaveChangesAsync(ct);
        }
        return new PolicyTestDb(connection, db);
    }

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await Connection.DisposeAsync();
    }
}

internal static class PolicySeeding
{
    /// <summary>
    /// Inserts a policy with a single published version and links it to the template
    /// <paramref name="typeKey"/>, bypassing the management service so enforcement tests do not
    /// depend on it.
    /// </summary>
    public static async Task<IssuancePolicyVersion> LinkPublishedPolicyAsync(
        CertificateRequestDbContext db,
        string typeKey,
        string[]? dnsSuffixes = null,
        string[]? ipRanges = null,
        string[]? algorithms = null,
        int? maxValidityDays = null,
        string[]? requesterRoles = null,
        KeyCustodyMode keyCustody = KeyCustodyMode.Any,
        string? name = null,
        CancellationToken ct = default)
    {
        var policy = new IssuancePolicy { Name = name ?? $"policy-{Guid.NewGuid():N}" };
        var version = new IssuancePolicyVersion
        {
            PolicyId = policy.Id,
            VersionNumber = 1,
            Status = IssuancePolicyVersionStatus.Published,
            AllowedDnsSuffixesJson = JsonSerializer.Serialize(dnsSuffixes ?? []),
            AllowedIpRangesJson = JsonSerializer.Serialize(ipRanges ?? []),
            AllowedKeyAlgorithmsJson = JsonSerializer.Serialize(algorithms ?? []),
            MaxValidityDays = maxValidityDays,
            AllowedRequesterRolesJson = JsonSerializer.Serialize(requesterRoles ?? []),
            KeyCustody = keyCustody,
            CreatedBy = "test",
            PublishedBy = "test",
            PublishedAtUtc = DateTime.UtcNow
        };
        db.IssuancePolicies.Add(policy);
        db.IssuancePolicyVersions.Add(version);
        var template = await db.CertificateTemplates.SingleAsync(t => t.TypeKey == typeKey, ct);
        template.IssuancePolicyId = policy.Id;
        await db.SaveChangesAsync(ct);
        return version;
    }
}

internal sealed class RecordingPolicyAuditLog : IAuditLogService
{
    public List<(string Action, string PerformedBy, Guid? ResourceId, string? ResourceName, string? Detail)> Entries { get; } = [];

    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
    {
        Entries.Add((action, performedBy, resourceId, resourceName, detail));
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

internal sealed class NullPolicyWebhookService : IWebhookService
{
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}
