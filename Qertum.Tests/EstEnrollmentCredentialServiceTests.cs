using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Est;
using Xunit;

namespace Qertum.Tests;

/// <summary>
/// No-op-except-recording audit log service for this test file. <c>RecordingAuditLogService</c> in
/// <c>CertificateRequestServiceTests.cs</c> is declared <c>file</c>-scoped and so isn't reachable here;
/// this is a local equivalent following the same pattern.
/// </summary>
file sealed class RecordingAuditLogService : IAuditLogService
{
    private readonly List<(string Action, string PerformedBy, Guid? ResourceId, string? ResourceName)> _entries = [];

    public IReadOnlyList<(string Action, string PerformedBy, Guid? ResourceId, string? ResourceName)> Entries => _entries;

    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
    {
        _entries.Add((action, performedBy, resourceId, resourceName));
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

public class EstEnrollmentCredentialServiceTests
{
    private static CertificateRequestDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;
        var context = new CertificateRequestDbContext(options, new EphemeralDataProtectionProvider());
        context.Database.OpenConnection();
        context.Database.EnsureCreated();
        return context;
    }

    [Fact]
    public async Task CreateAsync_persists_a_hashed_password_never_the_plaintext()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var db = CreateContext();
        var auditLog = new RecordingAuditLogService();
        var service = new EstEnrollmentCredentialService(db, auditLog);

        var created = await service.CreateAsync("device-fleet-1", "hunter2", "admin@test", cancellationToken: ct);

        Assert.Equal("device-fleet-1", created.Credential.Username);
        var stored = await db.EstEnrollmentCredentials.SingleAsync(ct);
        Assert.NotEqual("hunter2", stored.PasswordHash);
    }

    [Fact]
    public async Task CreateAsync_description_round_trips_through_GetAllAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var db = CreateContext();
        var service = new EstEnrollmentCredentialService(db, new RecordingAuditLogService());

        var created = await service.CreateAsync("device-fleet-1", "hunter2", "admin@test", "fleet-1 bootstrap devices", ct);
        Assert.Equal("fleet-1 bootstrap devices", created.Credential.Description);

        var all = await service.GetAllAsync(ct);
        var listed = Assert.Single(all);
        Assert.Equal("fleet-1 bootstrap devices", listed.Description);
    }

    [Fact]
    public async Task CheckAsync_TellsWrongPasswordFromDisabledFromUnknown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var db = CreateContext();
        var service = new EstEnrollmentCredentialService(db, new RecordingAuditLogService());
        var created = await service.CreateAsync("device-1", "correct-horse", "admin@test", cancellationToken: ct);

        Assert.Equal(EstCredentialOutcome.WrongPassword, (await service.CheckAsync("device-1", "wrong", ct)).Outcome);
        var ok = await service.CheckAsync("device-1", "correct-horse", ct);
        Assert.Equal((EstCredentialOutcome.Success, (Guid?)created.Credential.Id), (ok.Outcome, ok.CredentialId));
        var unknown = await service.CheckAsync("nobody", "anything", ct);
        Assert.Equal((EstCredentialOutcome.UnknownUsername, (Guid?)null), (unknown.Outcome, unknown.CredentialId));

        await service.SetEnabledAsync(created.Credential.Id, false, "admin@test", ct);
        var disabled = await service.CheckAsync("device-1", "correct-horse", ct);
        Assert.Equal((EstCredentialOutcome.Disabled, (Guid?)created.Credential.Id), (disabled.Outcome, disabled.CredentialId));
    }
}
