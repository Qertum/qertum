using System.Diagnostics;
using Qertum.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Tests;

file sealed class NullWebhookService : IWebhookService
{
    public Task<IReadOnlyList<Webhook>> GetAllAsync(CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Webhook>>([]);
    public Task<Webhook?> GetByIdAsync(WebhookId id, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<Webhook> CreateAsync(Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(webhook);
    public Task<Webhook?> UpdateAsync(WebhookId id, Webhook webhook, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult<Webhook?>(null);
    public Task<bool> DeleteAsync(WebhookId id, string performedBy, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task EnqueueEventAsync(WebhookEvent webhookEvent, CancellationToken cancellationToken = default) => Task.CompletedTask;
}

/// <summary>
/// No-op audit log service for unit tests — does not write to any database.
/// </summary>
file sealed class NullAuditLogService : IAuditLogService
{
    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
        => Task.CompletedTask;

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>([]);
}

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

file sealed class RecordingWithTraceIdAuditLogService : IAuditLogService
{
    private readonly List<AuditLogEntry> _entries = [];
    public IReadOnlyList<AuditLogEntry> Entries => _entries;

    public Task LogAsync(string action, string performedBy, Guid? resourceId = null,
        string? resourceName = null, string? detail = null, CancellationToken cancellationToken = default)
    {
        _entries.Add(new AuditLogEntry
        {
            Id = Guid.NewGuid(),
            Action = action,
            PerformedBy = performedBy,
            ResourceId = resourceId,
            ResourceName = resourceName,
            Detail = detail,
            OccurredAtUtc = DateTime.UtcNow,
            TraceId = Activity.Current?.TraceId.ToString()
        });
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100,
        CancellationToken cancellationToken = default)
        => Task.FromResult<IReadOnlyList<AuditLogEntry>>(_entries);
}

public sealed class CertificateRequestServiceTests
{
    private const string TestActor = "test-user";

    [Fact]
    public async Task CreateAsyncPersistsCertificateRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var createdRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "api.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        Assert.NotEqual(default(CertificateRequestId), createdRequest.Id);

        var storedRequest = await testScope.DbContext.CertificateRequests.SingleAsync(ct);
        Assert.Equal("api.contoso.local", storedRequest.CommonName);
        Assert.Equal("alice@contoso.local", storedRequest.RequestedBy);
        Assert.Equal(CertificateRequestStatus.Pending, storedRequest.Status);
    }

    [Fact]
    public async Task GetAllAsyncReturnsRequestsInDescendingCreatedOrder()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "first.contoso.local",
            RequestedBy = "first@contoso.local",
            CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        }, TestActor, ct);

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "second.contoso.local",
            RequestedBy = "second@contoso.local",
            CreatedAtUtc = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc)
        }, TestActor, ct);

        var result = await testScope.Service.GetAllAsync(cancellationToken: ct);

        Assert.Collection(result.Items,
            request => Assert.Equal("second.contoso.local", request.CommonName),
            request => Assert.Equal("first.contoso.local", request.CommonName));
    }

    [Fact]
    public async Task UpdateAsyncUpdatesExistingRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var createdRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "legacy.contoso.local",
            RequestedBy = "bob@contoso.local"
        }, TestActor, ct);

        var updatedRequest = await testScope.Service.UpdateAsync(createdRequest.Id, new CertificateRequest
        {
            CommonName = "modern.contoso.local",
            RequestedBy = "carol@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        Assert.NotNull(updatedRequest);
        Assert.Equal("modern.contoso.local", updatedRequest.CommonName);
        // An update must not reassign the requester: doing so would also transfer private-key access.
        Assert.Equal("bob@contoso.local", updatedRequest.RequestedBy);
        Assert.Equal(CertificateRequestStatus.Approved, updatedRequest.Status);
        Assert.True(updatedRequest.UpdatedAtUtc >= createdRequest.UpdatedAtUtc);
    }

    [Fact]
    public async Task UpdateAsync_AtEnforce_RejectsChangingToClassicalAlgorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "update-target.contoso.local",
            RequestedBy = "bob@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65
        }, TestActor, ct);

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        await Assert.ThrowsAsync<PqcPolicyViolationException>(async () =>
            await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
            {
                CommonName = "update-target.contoso.local",
                Status = CertificateRequestStatus.Pending,
                KeyAlgorithm = CertificateKeyAlgorithm.Rsa
            }, TestActor, ct));
    }

    [Fact]
    public async Task UpdateAsync_AtEnforce_AllowsCompliantAlgorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "update-ok.contoso.local",
            RequestedBy = "bob@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65
        }, TestActor, ct);

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        var updated = await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = "update-ok.contoso.local",
            Status = CertificateRequestStatus.Pending,
            KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP256
        }, TestActor, ct);

        Assert.NotNull(updated);
        Assert.Equal(CertificateKeyAlgorithm.HybridEcdsaP256, updated.KeyAlgorithm);
    }

    [Fact]
    public async Task UpdateAsyncPersistsTypeAndPropertiesJson()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var createdRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "original.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestActor, ct);

        var updatedRequest = await testScope.Service.UpdateAsync(createdRequest.Id, new CertificateRequest
        {
            CommonName = "updated.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer",
            PropertiesJson = "{\"dnsNames\":[\"updated.contoso.local\",\"www.updated.contoso.local\"]}"
        }, TestActor, ct);

        Assert.NotNull(updatedRequest);
        Assert.Equal("WebServer", updatedRequest.Type);
        Assert.Equal("{\"dnsNames\":[\"updated.contoso.local\",\"www.updated.contoso.local\"]}", updatedRequest.PropertiesJson);

        var stored = await testScope.DbContext.CertificateRequests.SingleAsync(ct);
        Assert.Equal(updatedRequest.PropertiesJson, stored.PropertiesJson);
    }

    [Fact]
    public async Task DeleteAsyncRemovesExistingRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var createdRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "delete.contoso.local",
            RequestedBy = "dave@contoso.local"
        }, TestActor, ct);

        var deleted = await testScope.Service.DeleteAsync(createdRequest.Id, TestActor, ct);
        var remaining = await testScope.Service.GetAllAsync(cancellationToken: ct);

        Assert.True(deleted);
        Assert.Empty(remaining.Items);
    }

    [Fact]
    public async Task DeleteAsyncRemovesRejectedRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var request = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = "delete-rejected.contoso.local",
            RequestedBy = "dave@contoso.local",
            Status = CertificateRequestStatus.Rejected
        };
        testScope.DbContext.CertificateRequests.Add(request);
        await testScope.DbContext.SaveChangesAsync(ct);

        Assert.True(await testScope.Service.DeleteAsync(request.Id, TestActor, ct));
        Assert.Null(await testScope.Service.GetByIdAsync(request.Id, ct));
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Approved)]
    [InlineData(CertificateRequestStatus.Processing)]
    [InlineData(CertificateRequestStatus.Issued)]
    [InlineData(CertificateRequestStatus.PendingRevocation)]
    [InlineData(CertificateRequestStatus.Revoked)]
    public async Task DeleteAsync_ProtectedLifecycleStatePreservesRequest(CertificateRequestStatus status)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var request = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = $"protected-{status}.contoso.local",
            RequestedBy = "dave@contoso.local",
            Status = status,
            SerialNumber = "A1B2C3",
            PqcSerialNumber = "D4E5F6",
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            RevokedAtUtc = status is CertificateRequestStatus.PendingRevocation or CertificateRequestStatus.Revoked
                ? DateTime.UtcNow
                : null
        };
        testScope.DbContext.CertificateRequests.Add(request);
        await testScope.DbContext.SaveChangesAsync(ct);

        await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            testScope.Service.DeleteAsync(request.Id, TestActor, ct));

        var preserved = await testScope.Service.GetByIdAsync(request.Id, ct);
        Assert.NotNull(preserved);
        Assert.Equal(status, preserved.Status);
        Assert.Equal("A1B2C3", preserved.SerialNumber);
        Assert.Equal("D4E5F6", preserved.PqcSerialNumber);
    }

    [Fact]
    public async Task DequeueNextApprovedAsyncProcessesApprovedRequestsInOrder()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var firstRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "first-queue.contoso.local",
            RequestedBy = "first.worker@contoso.local",
            CreatedAtUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        }, TestActor, ct);

        var secondRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "second-queue.contoso.local",
            RequestedBy = "second.worker@contoso.local",
            CreatedAtUtc = new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc)
        }, TestActor, ct);

        // Pending requests are not dequeued — admin approval is required first
        Assert.Null(await testScope.Service.DequeueNextApprovedAsync(ct));

        await testScope.Service.MarkAsApprovedAsync(firstRequest.Id, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(secondRequest.Id, TestActor, ct);

        var dequeuedFirst = await testScope.Service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(dequeuedFirst);
        Assert.Equal(firstRequest.Id, dequeuedFirst.Id);
        Assert.Equal(CertificateRequestStatus.Processing, dequeuedFirst.Status);

        // Simulate the worker marking the first request as issued before picking up the next
        await testScope.Service.MarkAsIssuedAsync(dequeuedFirst.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(1)
        }, TestActor, ct);

        var dequeuedSecond = await testScope.Service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(dequeuedSecond);
        Assert.Equal(secondRequest.Id, dequeuedSecond.Id);

        await testScope.Service.MarkAsIssuedAsync(dequeuedSecond.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(1)
        }, TestActor, ct);

        Assert.Null(await testScope.Service.DequeueNextApprovedAsync(ct));
    }

    [Fact]
    public async Task MarkAsIssuedAsyncUpdatesApprovedRequestStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var createdRequest = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "issued.contoso.local",
            RequestedBy = "issuer@contoso.local"
        }, TestActor, ct);

        await testScope.Service.MarkAsApprovedAsync(createdRequest.Id, TestActor, ct);

        var issuedRequest = await testScope.Service.MarkAsIssuedAsync(createdRequest.Id, new GeneratedCertificate
        {
            CertificatePem = "pem",
            PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        }, TestActor, ct);

        Assert.NotNull(issuedRequest);
        Assert.Equal(CertificateRequestStatus.Issued, issuedRequest.Status);
    }

    [Fact]
    public async Task UpdateAsync_WithNonExistentId_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var updatedRequest = await testScope.Service.UpdateAsync(Guid.NewGuid(), new CertificateRequest
        {
            CommonName = "modern.contoso.local",
            RequestedBy = "carol@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        Assert.Null(updatedRequest);
    }

    [Fact]
    public async Task MarkAsIssuedAsync_WithNonExistentId_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var issuedRequest = await testScope.Service.MarkAsIssuedAsync(Guid.NewGuid(), new GeneratedCertificate
        {
            CertificatePem = "pem",
            PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        }, TestActor, ct);

        Assert.Null(issuedRequest);
    }

    [Fact]
    public async Task DequeueNextApprovedAsync_WhenNoApprovedRequestsExist_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        // Create a pending request, but no approved requests
        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "pending.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        var nextRequest = await testScope.Service.DequeueNextApprovedAsync(ct);

        Assert.Null(nextRequest);
    }

    [Fact]
    public async Task DequeueNextApprovedAsync_RaceSafetyUnderConcurrentRequests()
    {
        var ct = TestContext.Current.CancellationToken;
        var testScope = await CreateTestScopeAsync();

        // Create one approved request
        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "concurrent.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        // Simulate 5 concurrent dequeues using separate DbContexts against the same Sqlite connection.
        var sharedConnection = testScope.Connection;
        var tasks = Enumerable.Range(0, 5).Select(async _ =>
        {
            var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
                .UseSqlite(sharedConnection)
                .Options;

            var dataProtection = new EphemeralDataProtectionProvider();
            var dbContext = new CertificateRequestDbContext(options, dataProtection);
            var service = new CertificateRequestService(dbContext, new NullAuditLogService(), new NullWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(dbContext, new Qertum.Services.Policies.IssuancePolicyEvaluator()));

            return await service.DequeueNextApprovedAsync(ct);
        }).ToList();

        var results = await Task.WhenAll(tasks);

        await testScope.DisposeAsync();

        // Only exactly one result should be non-null
        var successfulDequeues = results.Where(r => r != null).ToList();
        Assert.Single(successfulDequeues);
        Assert.Equal(CertificateRequestStatus.Processing, successfulDequeues.First()!.Status);
    }

    [Fact]
    public async Task SetupOrUpdateSettingsAsync_CreatesRowOnFirstCall()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var settings = new CaSettings
        {
            OrganizationName = "Contoso",
            OrganizationalUnit = "IT",
            Country = "US",
            State = "WA",
            Locality = "Seattle",
            ExpiringSoonDays = 30,
            CrlDistributionPoint = "http://crl.contoso.local/ca.crl"
        };

        var result = await testScope.Service.SetupOrUpdateSettingsAsync(settings, TestActor, ct);

        Assert.Equal(1, result.Id);
        Assert.Equal("Contoso", result.OrganizationName);
        Assert.Equal("http://crl.contoso.local/ca.crl", result.CrlDistributionPoint);

        var stored = await testScope.DbContext.Settings.SingleAsync(ct);
        Assert.Equal(1, stored.Id);
        Assert.Equal("http://crl.contoso.local/ca.crl", stored.CrlDistributionPoint);
    }

    [Fact]
    public async Task SetupOrUpdateSettingsAsync_UpdatesExistingRowIncludingCrlDistributionPoint()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var initial = new CaSettings
        {
            OrganizationName = "Contoso",
            ExpiringSoonDays = 30,
            CrlDistributionPoint = "http://crl.contoso.local/ca.crl"
        };
        await testScope.Service.SetupOrUpdateSettingsAsync(initial, TestActor, ct);

        var updated = new CaSettings
        {
            OrganizationName = "Contoso Updated",
            ExpiringSoonDays = 14,
            CrlDistributionPoint = "http://crl2.contoso.local/new.crl"
        };
        var result = await testScope.Service.SetupOrUpdateSettingsAsync(updated, TestActor, ct);

        Assert.Equal("Contoso Updated", result.OrganizationName);
        Assert.Equal(14, result.ExpiringSoonDays);
        Assert.Equal("http://crl2.contoso.local/new.crl", result.CrlDistributionPoint);

        var stored = await testScope.DbContext.Settings.SingleAsync(ct);
        Assert.Equal("http://crl2.contoso.local/new.crl", stored.CrlDistributionPoint);
    }

    [Fact]
    public async Task SavingSettings_DoesNotResetTheDeltaCrlBase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso" }, TestActor, ct);

        // Simulate the full-CRL endpoint recording a base, the way RecordBaseCrlAsync will.
        testScope.DbContext.Settings.Single().BaseCrlNumber = 5;
        testScope.DbContext.Settings.Single().BaseCrlThisUpdateUtc = new DateTime(2026, 8, 27, 12, 0, 0, DateTimeKind.Utc);
        await testScope.DbContext.SaveChangesAsync(ct);

        // An operator editing an unrelated field (here: OrganizationName) must not disturb the base.
        var updated = await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Contoso Renamed" }, TestActor, ct);

        Assert.Equal(5, updated.BaseCrlNumber);
        Assert.Equal(new DateTime(2026, 8, 27, 12, 0, 0, DateTimeKind.Utc), updated.BaseCrlThisUpdateUtc);
    }

    [Fact]
    public async Task SetPqcStageAsync_Persists_AndAGeneralSaveCarriesItAcross()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);
        Assert.Equal(PqcStage.Enforce, (await testScope.DbContext.Settings.SingleAsync(ct)).PqcStage);

        var updated = await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { OrganizationName = "Contoso", PqcStage = PqcStage.Off }, TestActor, ct);

        Assert.Equal(PqcStage.Enforce, updated.PqcStage);
        Assert.Equal("Contoso", updated.OrganizationName);
    }

    [Fact]
    public async Task SetupOrUpdateSettingsAsync_CrlDistributionPointCanBeCleared()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetupOrUpdateSettingsAsync(new CaSettings
        {
            OrganizationName = "Contoso",
            CrlDistributionPoint = "http://crl.contoso.local/ca.crl"
        }, TestActor, ct);

        var result = await testScope.Service.SetupOrUpdateSettingsAsync(new CaSettings
        {
            OrganizationName = "Contoso",
            CrlDistributionPoint = null
        }, TestActor, ct);

        Assert.Null(result.CrlDistributionPoint);

        var stored = await testScope.DbContext.Settings.SingleAsync(ct);
        Assert.Null(stored.CrlDistributionPoint);
    }

    /// <summary>
    /// Regression for the former IMPROVEMENTS.md audit §3.4: the update path hand-copied a fixed list of fields and
    /// omitted AcmeAutoApprove, so the Settings toggle bound to it was a permanent no-op once the row
    /// existed. Covers the ACME allowlist added alongside it for the same reason.
    /// </summary>
    [Fact]
    public async Task SetupOrUpdateSettingsAsync_PersistsEveryFieldOnUpdate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetupOrUpdateSettingsAsync(new CaSettings
        {
            OrganizationName = "Contoso"
        }, TestActor, ct);

        var result = await testScope.Service.SetupOrUpdateSettingsAsync(new CaSettings
        {
            OrganizationName = "Contoso",
            AcmeAutoApprove = true,
            AutoRenewalEnabled = true,
            AcmeChallengeAllowedNetworksJson = """["10.1.0.0/16"]"""
        }, TestActor, ct);

        Assert.True(result.AcmeAutoApprove);
        Assert.True(result.AutoRenewalEnabled);
        Assert.Equal("""["10.1.0.0/16"]""", result.AcmeChallengeAllowedNetworksJson);

        var stored = await testScope.DbContext.Settings.SingleAsync(ct);
        Assert.True(stored.AcmeAutoApprove);
        Assert.True(stored.AutoRenewalEnabled);
        Assert.Equal("""["10.1.0.0/16"]""", stored.AcmeChallengeAllowedNetworksJson);
    }

    [Fact]
    public async Task GetAllAsync_PaginatesCorrectlyAcrossPages()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var baseTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // Create 12 requests with deterministic CreatedAtUtc so ordering is stable
        for (var i = 1; i <= 12; i++)
        {
            await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = $"cert{i:D2}.contoso.local",
                RequestedBy = "alice@contoso.local",
                CreatedAtUtc = baseTime.AddMinutes(i)
            }, TestActor, ct);
        }

        // Page 1 of 3 (pageSize = 5)
        var page1 = await testScope.Service.GetAllAsync(page: 1, pageSize: 5, cancellationToken: ct);
        Assert.Equal(12, page1.TotalCount);
        Assert.Equal(3, page1.TotalPages);
        Assert.Equal(5, page1.Items.Count);
        Assert.Equal("cert12.contoso.local", page1.Items[0].CommonName); // newest first

        // Page 2 of 3
        var page2 = await testScope.Service.GetAllAsync(page: 2, pageSize: 5, cancellationToken: ct);
        Assert.Equal(5, page2.Items.Count);
        Assert.Equal("cert07.contoso.local", page2.Items[0].CommonName);

        // Page 3 of 3 — partial page
        var page3 = await testScope.Service.GetAllAsync(page: 3, pageSize: 5, cancellationToken: ct);
        Assert.Equal(2, page3.Items.Count);
        Assert.Equal("cert02.contoso.local", page3.Items[0].CommonName);
        Assert.Equal("cert01.contoso.local", page3.Items[1].CommonName);

        // Pages 1 and 2 share no items
        var page1Ids = page1.Items.Select(r => r.Id).ToHashSet();
        Assert.DoesNotContain(page2.Items[0].Id, page1Ids);
    }

    [Fact]
    public async Task GetAllAsync_PageBeyondEnd_ReturnsEmptyItems()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "only.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        var result = await testScope.Service.GetAllAsync(page: 99, pageSize: 10, cancellationToken: ct);

        Assert.Equal(1, result.TotalCount);
        Assert.Empty(result.Items);
    }

    [Fact]
    public async Task GetDashboardSummaryAsync_RecentRequestsCappedAtTenAndOrderedByMostRecentUpdate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var baseTime = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        for (var i = 1; i <= 15; i++)
        {
            await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = $"cert{i:D2}.contoso.local",
                RequestedBy = "alice@contoso.local"
            }, TestActor, ct);
        }

        // CreateAsync always sets UpdatedAtUtc = DateTime.UtcNow, so set deterministic
        // timestamps directly so the ordering is predictable in the assertion below.
        var rows = await testScope.DbContext.CertificateRequests
            .OrderBy(r => r.CommonName)
            .ToListAsync(ct);
        for (var i = 0; i < rows.Count; i++)
            rows[i].UpdatedAtUtc = baseTime.AddMinutes(i + 1);
        await testScope.DbContext.SaveChangesAsync(ct);

        var summary = await testScope.Service.GetDashboardSummaryAsync(ct);

        Assert.Equal(15, summary.TotalCount);
        Assert.Equal(10, summary.RecentRequests.Count);

        // cert15 (latest) … cert06 should be present; cert01–cert05 should not
        var names = summary.RecentRequests.Select(r => r.CommonName).ToList();
        Assert.Equal("cert15.contoso.local", names[0]);
        Assert.Equal("cert06.contoso.local", names[9]);
        Assert.DoesNotContain("cert05.contoso.local", names);
    }

    [Fact]
    public async Task GetDashboardSummaryAsync_UsesExpiringSoonDaysFromSettings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var now = DateTime.UtcNow;

        // Issue a certificate that expires in 10 days
        var req = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "expiring.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(req.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(req.Id, new GeneratedCertificate
        {
            CertificatePem = "pem",
            PrivateKeyPem = "key",
            ValidFrom = now.AddDays(-1),
            ValidTo = now.AddDays(10)
        }, TestActor, ct);

        // ExpiringSoonDays = 30 → cert expiring in 10 days is "expiring soon"
        await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 }, TestActor, ct);
        var summary30 = await testScope.Service.GetDashboardSummaryAsync(ct);
        Assert.Equal(1, summary30.ExpiringSoonCount);
        Assert.Equal(0, summary30.ValidCount);

        // ExpiringSoonDays = 5 → cert expiring in 10 days is NOT "expiring soon"
        await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 5 }, TestActor, ct);
        var summary5 = await testScope.Service.GetDashboardSummaryAsync(ct);
        Assert.Equal(0, summary5.ExpiringSoonCount);
        Assert.Equal(1, summary5.ValidCount);
    }

    [Fact]
    public async Task GetDashboardSummaryAsync_EmptyTableReturnsZeroedCounts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        // The aggregate query groups over a constant key, so an empty table yields no row at all.
        var summary = await testScope.Service.GetDashboardSummaryAsync(ct);

        Assert.Equal(0, summary.TotalCount);
        Assert.Equal(0, summary.PendingCount);
        Assert.Equal(0, summary.ApprovedCount);
        Assert.Equal(0, summary.RejectedCount);
        Assert.Equal(0, summary.IssuedCount);
        Assert.Equal(0, summary.ValidCount);
        Assert.Equal(0, summary.ExpiringSoonCount);
        Assert.Equal(0, summary.ExpiredCount);
        Assert.Equal(0, summary.RevokedCount);
        Assert.Empty(summary.RecentRequests);
    }

    [Fact]
    public async Task GetDashboardSummaryAsync_CountsEveryStatusBucket()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        var now = DateTime.UtcNow;

        await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, ExpiringSoonDays = 30 }, TestActor, ct);

        async Task<CertificateRequestId> CreateAsync(string commonName)
        {
            var created = await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = "alice@contoso.local"
            }, TestActor, ct);
            return created.Id;
        }

        async Task IssueAsync(string commonName, DateTime validTo)
        {
            var id = await CreateAsync(commonName);
            await testScope.Service.MarkAsApprovedAsync(id, TestActor, ct);
            await testScope.Service.MarkAsIssuedAsync(id, new GeneratedCertificate
            {
                CertificatePem = "pem",
                PrivateKeyPem = "key",
                ValidFrom = now.AddDays(-1),
                ValidTo = validTo
            }, TestActor, ct);
        }

        await CreateAsync("pending.contoso.local");

        var approvedId = await CreateAsync("approved.contoso.local");
        await testScope.Service.MarkAsApprovedAsync(approvedId, TestActor, ct);

        var rejectedId = await CreateAsync("rejected.contoso.local");
        await testScope.Service.MarkAsRejectedAsync(rejectedId, TestActor, ct);

        await IssueAsync("valid.contoso.local", now.AddDays(365));
        await IssueAsync("expiring.contoso.local", now.AddDays(10));
        await IssueAsync("expired.contoso.local", now.AddDays(-1));

        var revokedId = await CreateAsync("revoked.contoso.local");
        await testScope.Service.MarkAsApprovedAsync(revokedId, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(revokedId, new GeneratedCertificate
        {
            CertificatePem = "pem",
            PrivateKeyPem = "key",
            ValidFrom = now.AddDays(-1),
            ValidTo = now.AddDays(365)
        }, TestActor, ct);
        await testScope.Service.MarkAsRevokedAsync(revokedId, "superseded", TestActor, ct);

        var summary = await testScope.Service.GetDashboardSummaryAsync(ct);

        Assert.Equal(7, summary.TotalCount);
        Assert.Equal(1, summary.PendingCount);
        Assert.Equal(1, summary.ApprovedCount);
        Assert.Equal(1, summary.RejectedCount);
        // IssuedCount deliberately includes Revoked: 3 issued + 1 revoked.
        Assert.Equal(4, summary.IssuedCount);
        Assert.Equal(1, summary.ValidCount);
        Assert.Equal(1, summary.ExpiringSoonCount);
        Assert.Equal(1, summary.ExpiredCount);
        Assert.Equal(1, summary.RevokedCount);
    }

    [Fact]
    public async Task RenewAsync_CreatesPendingRequestWithRenewedFromId()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "original.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer",
            PropertiesJson = "{\"dnsNames\":[\"original.contoso.local\"]}"
        }, TestActor, ct);

        var renewal = await testScope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.NotEqual(original.Id, renewal.Id);
        Assert.Equal(CertificateRequestStatus.Pending, renewal.Status);
        Assert.Equal(original.Id, renewal.RenewedFromId);
    }

    [Fact]
    public async Task RenewAsync_RenewsAPairAsAPair()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "renew-pair.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa87MlKem1024
        }, TestActor, ct);

        var renewal = await testScope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.Equal(CertificateKeyAlgorithm.PairMlDsa87MlKem1024, renewal.KeyAlgorithm);
        Assert.Equal(original.Id, renewal.RenewedFromId);
    }

    [Fact]
    public async Task RenewAsync_AtEnforce_RejectsRenewingClassicalOriginCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "renew-classical.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa
        }, TestActor, ct);

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        await Assert.ThrowsAsync<PqcPolicyViolationException>(async () =>
            await testScope.Service.RenewAsync(original.Id, TestActor, ct));
    }

    [Fact]
    public async Task RenewAsync_AtEnforce_AllowsRenewingPqcOriginCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "renew-pqc.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.MlDsa87
        }, TestActor, ct);

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        var renewal = await testScope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa87, renewal.KeyAlgorithm);
    }

    [Fact]
    public async Task RenewAsync_CopiesCommonNameTypeAndPropertiesJson()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "copy-check.contoso.local",
            RequestedBy = "bob@contoso.local",
            Type = "WebServer",
            PropertiesJson = "{\"dnsNames\":[\"alt.contoso.local\"]}"
        }, TestActor, ct);

        var renewal = await testScope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.Equal(original.CommonName, renewal.CommonName);
        Assert.Equal(original.Type, renewal.Type);
        Assert.Equal(original.PropertiesJson, renewal.PropertiesJson);
    }

    [Fact]
    public async Task RenewAsync_WithNonExistentId_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var result = await testScope.Service.RenewAsync(Guid.NewGuid(), TestActor, ct);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetCertsNeedingAutoRenewalAsync_ReturnsCertNearingExpiry()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var cert = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "expiring.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(cert.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(cert.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddDays(25)
        }, TestActor, ct);

        var result = await testScope.Service.GetCertsNeedingAutoRenewalAsync(30, ct);

        Assert.Single(result);
        Assert.Equal(cert.Id, result[0].Id);
    }

    [Fact]
    public async Task GetCertsNeedingAutoRenewalAsync_ExcludesCertWithActivePendingRenewal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var cert = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "renewed.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(cert.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(cert.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddDays(25)
        }, TestActor, ct);

        // An existing Pending renewal already exists
        await testScope.Service.RenewAsync(cert.Id, TestActor, ct);

        var result = await testScope.Service.GetCertsNeedingAutoRenewalAsync(30, ct);

        Assert.Empty(result);
    }

    [Fact]
    public async Task GetCertsNeedingAutoRenewalAsync_ExcludesCertWithActiveIssuedRenewal()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var cert = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "already-renewed.contoso.local",
            RequestedBy = "alice@contoso.local",
            Type = "WebServer"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(cert.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(cert.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = "key",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddDays(25)
        }, TestActor, ct);

        // Renewal exists and is already Issued
        var renewal = await testScope.Service.RenewAsync(cert.Id, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(renewal!.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(renewal.Id, new GeneratedCertificate
        {
            CertificatePem = "pem2", PrivateKeyPem = "key2",
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(1)
        }, TestActor, ct);

        var result = await testScope.Service.GetCertsNeedingAutoRenewalAsync(30, ct);

        Assert.Empty(result);
    }

    [Fact]
    public async Task GetCertsNeedingAutoRenewalAsync_ExcludesAcmeIssuedCerts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var cert = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "acme.contoso.local",
            RequestedBy = "acme-client",
            Type = "WebServer",
            CsrPem = "fake-csr-pem"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(cert.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(cert.Id, new GeneratedCertificate
        {
            CertificatePem = "pem", PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddDays(25)
        }, TestActor, ct);

        var result = await testScope.Service.GetCertsNeedingAutoRenewalAsync(30, ct);

        Assert.Empty(result);
    }

    [Fact]
    public async Task ResetStuckProcessingAsync_RecoversProcessingRowsToApproved()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "stuck.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        var dequeued = await testScope.Service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(dequeued);
        Assert.Equal(CertificateRequestStatus.Processing, dequeued.Status);

        // Row is stuck in Processing — not visible to the dequeue loop
        Assert.Null(await testScope.Service.DequeueNextApprovedAsync(ct));

        var recovered = await testScope.Service.ResetStuckProcessingAsync(ct);
        Assert.Equal(1, recovered);

        // After recovery the row is dequeued again
        var requeued = await testScope.Service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(requeued);
        Assert.Equal(created.Id, requeued.Id);
        Assert.Equal(CertificateRequestStatus.Processing, requeued.Status);
    }

    [Fact]
    public async Task UpdateAsync_WritesAuditLogEntry()
    {
        var ct = TestContext.Current.CancellationToken;
        var auditLog = new RecordingAuditLogService();
        await using var testScope = await CreateTestScopeAsync(auditLog);

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "audit.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = "audit-updated.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Pending
        }, TestActor, ct);

        Assert.Contains(auditLog.Entries, e =>
            e.Action == "Updated" && e.PerformedBy == TestActor && e.ResourceId == created.Id);
    }

    [Fact]
    public async Task DeleteAsync_WritesAuditLogEntry()
    {
        var ct = TestContext.Current.CancellationToken;
        var auditLog = new RecordingAuditLogService();
        await using var testScope = await CreateTestScopeAsync(auditLog);

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "delete-audit.contoso.local",
            RequestedBy = "bob@contoso.local"
        }, TestActor, ct);

        await testScope.Service.DeleteAsync(created.Id, TestActor, ct);

        Assert.Contains(auditLog.Entries, e =>
            e.Action == "Deleted" && e.PerformedBy == TestActor && e.ResourceId == created.Id);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Issued,   CertificateRequestStatus.Pending)]
    [InlineData(CertificateRequestStatus.Issued,   CertificateRequestStatus.Approved)]
    [InlineData(CertificateRequestStatus.Revoked,  CertificateRequestStatus.Pending)]
    [InlineData(CertificateRequestStatus.Rejected, CertificateRequestStatus.Approved)]
    public async Task UpdateAsync_InvalidStateTransition_ThrowsInvalidStateTransitionException(
        CertificateRequestStatus initial, CertificateRequestStatus target)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "transition-guard.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = initial
        }, TestActor, ct);

        await Assert.ThrowsAsync<InvalidStateTransitionException>(async () =>
            await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
            {
                CommonName = created.CommonName,
                RequestedBy = created.RequestedBy,
                Status = target
            }, TestActor, ct));
    }

    [Fact]
    public async Task UpdateAsync_ValidTransition_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "valid-transition.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        var updated = await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = created.CommonName,
            RequestedBy = created.RequestedBy,
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        Assert.NotNull(updated);
        Assert.Equal(CertificateRequestStatus.Approved, updated.Status);
    }

    [Fact]
    public async Task MarkAsRejectedWithReasonAsync_ProcessingRequest_SetsRejectedWithReason()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "fail.contoso.local",
            RequestedBy = "worker@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        var dequeued = await testScope.Service.DequeueNextApprovedAsync(ct);
        Assert.NotNull(dequeued);
        Assert.Equal(CertificateRequestStatus.Processing, dequeued.Status);

        // Consumer permanently rejects with a reason
        var reason = "CryptographicException on attempt 3: bad key";
        var rejected = await testScope.Service.MarkAsRejectedWithReasonAsync(
            dequeued.Id, reason, "queue-consumer", ct);

        Assert.NotNull(rejected);
        Assert.Equal(CertificateRequestStatus.Rejected, rejected.Status);
        Assert.Equal(reason, rejected.FailureReason);
    }

    [Fact]
    public async Task MarkAsRejectedWithReasonAsync_IssuedRequest_ReturnsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "issued.contoso.local",
            RequestedBy = "worker@contoso.local",
            Status = CertificateRequestStatus.Issued
        }, TestActor, ct);

        var result = await testScope.Service.MarkAsRejectedWithReasonAsync(
            created.Id, "some reason", "queue-consumer", ct);

        Assert.Null(result);
    }

    [Fact]
    public async Task MarkAsRejectedAsync_PendingRequest_HumanRejectionLeavesFailureReasonNull()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "human-rejected.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        var rejected = await testScope.Service.MarkAsRejectedAsync(created.Id, TestActor, ct);

        Assert.NotNull(rejected);
        Assert.Equal(CertificateRequestStatus.Rejected, rejected.Status);
        Assert.Null(rejected.FailureReason);
    }

    [Fact]
    public async Task AuditLog_PopulatesTraceId_WhenInsideActivity()
    {
        var ct = TestContext.Current.CancellationToken;
        var auditLog = new RecordingWithTraceIdAuditLogService();
        await using var testScope = await CreateTestScopeAsync(auditLog);

        using var activity = new ActivitySource("test").StartActivity();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "trace-id-test.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        // The AuditLogService captures Activity.Current?.TraceId
        Assert.All(auditLog.Entries, e =>
        {
            if (activity is not null)
                Assert.NotNull(e.TraceId);
        });
    }

    [Fact]
    public async Task CreateAsync_DuplicateActiveCommonName_ThrowsDuplicateRequestException()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "duplicate.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        await Assert.ThrowsAsync<DuplicateRequestException>(async () =>
            await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = "duplicate.contoso.local",
                RequestedBy = "bob@contoso.local"
            }, TestActor, ct));
    }

    [Fact]
    public async Task CreateAsync_AtEnforce_RejectsClassicalAlgorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        await Assert.ThrowsAsync<PqcPolicyViolationException>(async () =>
            await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = "classical.contoso.local",
                RequestedBy = "alice@contoso.local",
                KeyAlgorithm = CertificateKeyAlgorithm.Rsa
            }, TestActor, ct));
    }

    [Fact]
    public async Task CreateAsync_AtEnforce_AllowsHybridAndPqcAlgorithms()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        var mlDsa = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "mldsa.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65
        }, TestActor, ct);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65, mlDsa.KeyAlgorithm);

        var hybrid = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "hybrid.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP256
        }, TestActor, ct);
        Assert.Equal(CertificateKeyAlgorithm.HybridEcdsaP256, hybrid.KeyAlgorithm);

        var pair = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "mail-pair.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768
        }, TestActor, ct);
        Assert.Equal(CertificateKeyAlgorithm.PairMlDsa65MlKem768, pair.KeyAlgorithm);
    }

    [Fact]
    public async Task CreateAsync_AtEnforce_NullKeyAlgorithmTreatedAsRsaAndRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.SetPqcStageAsync(PqcStage.Enforce, TestActor, ct);

        await Assert.ThrowsAsync<PqcPolicyViolationException>(async () =>
            await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = "no-algo.contoso.local",
                RequestedBy = "alice@contoso.local"
                // KeyAlgorithm left null — defaults to Rsa at generation time, so the policy
                // check must treat it the same way.
            }, TestActor, ct));
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Rejected)]
    [InlineData(CertificateRequestStatus.Revoked)]
    public async Task CreateAsync_TerminalStateSameCn_Succeeds(CertificateRequestStatus terminalStatus)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "reuse.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = terminalStatus
        }, TestActor, ct);

        // Creating a new request with the same CN should succeed because the previous is in a terminal state
        var second = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "reuse.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        Assert.NotNull(second);
        Assert.Equal(CertificateRequestStatus.Pending, second.Status);
    }

    [Fact]
    public async Task GetAllRevokedForCrlAsync_ReturnsEveryRevokedRow_NotJustTheFirstPage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        // One more than the largest page size the paged API allows. A CRL that stops at a page
        // boundary reports the omitted certificates as *not revoked* — fail-open.
        const int revokedCount = 501;
        var revokedAt = new DateTime(2026, 8, 18, 0, 0, 0, DateTimeKind.Utc);
        for (var i = 0; i < revokedCount; i++)
        {
            testScope.DbContext.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = $"revoked-{i:D4}.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.Revoked,
                CertificatePem = $"-----BEGIN CERTIFICATE-----\nplaceholder-{i}\n-----END CERTIFICATE-----",
                RevokedAtUtc = revokedAt.AddSeconds(i),
                RevocationReason = "superseded"
            });
        }

        // A non-revoked row must not leak into the CRL.
        testScope.DbContext.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "live.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Issued
        });

        await testScope.DbContext.SaveChangesAsync(ct);

        var all = await testScope.Service.GetAllRevokedForCrlAsync(ct);

        Assert.Equal(revokedCount, all.Count);
        Assert.All(all, r => Assert.False(string.IsNullOrWhiteSpace(r.CertificatePem)));
        Assert.All(all, r => Assert.Equal("superseded", r.RevocationReason));
        Assert.Equal(revokedCount, all.Select(r => r.Id).Distinct().Count());
    }

    [Fact]
    public async Task GetRevokedSinceForCrlAsync_OnlyReturnsRowsRevokedAfterTheGivenInstant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var baseline = new DateTime(2026, 8, 27, 0, 0, 0, DateTimeKind.Utc);
        testScope.DbContext.CertificateRequests.AddRange(
            new CertificateRequest
            {
                CommonName = "before-base.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.Revoked,
                CertificatePem = "-----BEGIN CERTIFICATE-----\nplaceholder-before\n-----END CERTIFICATE-----",
                RevokedAtUtc = baseline.AddSeconds(-1)
            },
            new CertificateRequest
            {
                CommonName = "after-base.contoso.local",
                RequestedBy = "alice@contoso.local",
                Status = CertificateRequestStatus.Revoked,
                CertificatePem = "-----BEGIN CERTIFICATE-----\nplaceholder-after\n-----END CERTIFICATE-----",
                RevokedAtUtc = baseline.AddSeconds(1)
            });
        await testScope.DbContext.SaveChangesAsync(ct);

        var sinceBase = await testScope.Service.GetRevokedSinceForCrlAsync(baseline, ct);

        Assert.Single(sinceBase);
        Assert.Equal("after-base.contoso.local", sinceBase[0].CommonName);
    }

    [Fact]
    public async Task RecordBaseCrlAsync_PersistsTheNumberAndTimestamp()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        await testScope.Service.SetupOrUpdateSettingsAsync(new CaSettings { PqcStage = PqcStage.Off }, TestActor, ct);

        var thisUpdate = new DateTime(2026, 8, 27, 12, 0, 0, DateTimeKind.Utc);
        await testScope.Service.RecordBaseCrlAsync(crlNumber: 3, thisUpdateUtc: thisUpdate, ct);

        var settings = await testScope.Service.GetSettingsAsync(ct);
        Assert.Equal(3, settings.BaseCrlNumber);
        Assert.Equal(thisUpdate, settings.BaseCrlThisUpdateUtc);
    }

    [Fact]
    public async Task DeltaCrlFlow_BaseThenDeltaAgreeOnWhatWasRevokedSince()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();
        await testScope.Service.SetupOrUpdateSettingsAsync(
            new CaSettings { PqcStage = PqcStage.Off, DeltaCrlEnabled = true }, TestActor, ct);

        // Simulate the full-CRL endpoint publishing a base with nothing revoked yet.
        var baseCrlNumber = await testScope.Service.ClaimNextCrlNumberAsync(ct);
        var baseThisUpdate = DateTime.UtcNow;
        await testScope.Service.RecordBaseCrlAsync(baseCrlNumber, baseThisUpdate, ct);

        // A revocation happens after the base was published.
        await Task.Delay(10, ct); // ensure a strictly later timestamp
        testScope.DbContext.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "post-base.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Revoked,
            CertificatePem = "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----",
            RevokedAtUtc = DateTime.UtcNow
        });
        await testScope.DbContext.SaveChangesAsync(ct);

        var settings = await testScope.Service.GetSettingsAsync(ct);
        var sinceBase = await testScope.Service.GetRevokedSinceForCrlAsync(settings.BaseCrlThisUpdateUtc!.Value, ct);

        Assert.Single(sinceBase);
        Assert.Equal("post-base.contoso.local", sinceBase[0].CommonName);
        Assert.Equal(baseCrlNumber, settings.BaseCrlNumber);
    }

    [Fact]
    public async Task MarkAsIssuedAsync_PersistsSerialNumber()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var request = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "serial.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        await testScope.Service.MarkAsIssuedAsync(request.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nplaceholder\n-----END PRIVATE KEY-----",
            SerialNumber = "4A2F91C7",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var stored = await testScope.Service.GetByIdAsync(request.Id, ct);
        Assert.Equal("4A2F91C7", stored!.SerialNumber);
    }

    [Fact]
    public async Task MarkAsIssuedAsync_DuplicateSerialNumber_IsRejectedByTheDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        async Task<CertificateRequest> IssueAsync(string commonName)
        {
            var created = await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = "alice@contoso.local"
            }, TestActor, ct);

            return (await testScope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
            {
                CertificatePem = $"-----BEGIN CERTIFICATE-----\n{commonName}\n-----END CERTIFICATE-----",
                SerialNumber = "0BADC0DE",
                ValidFrom = DateTime.UtcNow,
                ValidTo = DateTime.UtcNow.AddDays(365)
            }, cancellationToken: ct))!;
        }

        await IssueAsync("first.contoso.local");

        // A CA must never sign two certificates under one serial. The unique index is what turns a
        // collision into a loud failure the consumer retries, instead of a silent misissuance.
        await Assert.ThrowsAnyAsync<DbUpdateException>(async () => await IssueAsync("second.contoso.local"));
    }

    [Fact]
    public async Task MarkAsIssuedAsync_PersistsThePqcSerialOfAPair()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var request = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "pqc-serial.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        await testScope.Service.MarkAsIssuedAsync(request.Id, new GeneratedCertificate
        {
            CertificatePem = "classical",
            PqcCertificatePem = "pqc",
            SerialNumber = "11AA",
            PqcSerialNumber = "22BB",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, cancellationToken: ct);

        var stored = await testScope.Service.GetByIdAsync(request.Id, ct);
        Assert.Equal("22BB", stored!.PqcSerialNumber);
    }

    [Fact]
    public async Task MarkAsIssuedAsync_DuplicatePqcSerialNumber_IsRejectedByTheDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        async Task IssueAsync(string commonName, string classicalSerial)
        {
            var created = await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = "alice@contoso.local"
            }, TestActor, ct);

            await testScope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
            {
                CertificatePem = commonName,
                PqcCertificatePem = commonName,
                SerialNumber = classicalSerial,
                PqcSerialNumber = "0DDBA11",
                ValidFrom = DateTime.UtcNow,
                ValidTo = DateTime.UtcNow.AddDays(365)
            }, cancellationToken: ct);
        }

        await IssueAsync("first-pair.contoso.local", "01");

        await Assert.ThrowsAnyAsync<DbUpdateException>(async () => await IssueAsync("second-pair.contoso.local", "02"));
    }

    // OCSP looks certificates up by serial. With only the classical serial stored, the responder
    // answered "unknown" for the PQC certificate of a pair, revoked or not.
    [Fact]
    public async Task GetRevocationStatusesAsync_AnswersForThePqcCertificateOfAPair()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        async Task<CertificateRequestId> IssueAsync(string commonName, string serial, string pqcSerial)
        {
            var created = await testScope.Service.CreateAsync(new CertificateRequest
            {
                CommonName = commonName,
                RequestedBy = "alice@contoso.local"
            }, TestActor, ct);
            await testScope.Service.MarkAsApprovedAsync(created.Id, TestActor, ct);
            await testScope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
            {
                CertificatePem = commonName,
                PqcCertificatePem = commonName,
                SerialNumber = serial,
                PqcSerialNumber = pqcSerial,
                ValidFrom = DateTime.UtcNow,
                ValidTo = DateTime.UtcNow.AddDays(365)
            }, TestActor, ct);
            return created.Id;
        }

        await IssueAsync("good-pair.contoso.local", "A1", "A2");
        var revokedId = await IssueAsync("revoked-pair.contoso.local", "B1", "B2");
        await testScope.Service.MarkAsRevokedAsync(revokedId, "keyCompromise", TestActor, ct);

        var statuses = await testScope.Service.GetRevocationStatusesAsync(["A1", "A2", "B1", "B2"], ct);

        Assert.Equal(OcspCertificateState.Good, statuses["A2"].State);
        Assert.Equal(OcspCertificateState.Revoked, statuses["B1"].State);
        Assert.Equal(OcspCertificateState.Revoked, statuses["B2"].State);
        Assert.Equal("keyCompromise", statuses["B2"].RevocationReason);
    }

    // Both certificates of an ML-DSA + ML-KEM pair are looked up by serial, like a hybrid pair.
    [Fact]
    public async Task GetRevocationStatusesAsync_AnswersForBothCertificatesOfAnMlDsaMlKemPair()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "mail-pair.contoso.local",
            RequestedBy = "alice@contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(created.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "mail-pair",
            PqcCertificatePem = "mail-pair",
            SerialNumber = "C1",
            PqcSerialNumber = "C2",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, TestActor, ct);

        var good = await testScope.Service.GetRevocationStatusesAsync(["C1", "C2"], ct);
        Assert.Equal(OcspCertificateState.Good, good["C2"].State);

        await testScope.Service.MarkAsRevokedAsync(created.Id, "keyCompromise", TestActor, ct);
        var revoked = await testScope.Service.GetRevocationStatusesAsync(["C1", "C2"], ct);
        Assert.Equal(OcspCertificateState.Revoked, revoked["C1"].State);
        Assert.Equal(OcspCertificateState.Revoked, revoked["C2"].State);
    }

    [Fact]
    public async Task RevokedForCrlQueries_CarryThePqcCertificateOfAPair()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "crl-pair.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);
        await testScope.Service.MarkAsApprovedAsync(created.Id, TestActor, ct);
        await testScope.Service.MarkAsIssuedAsync(created.Id, new GeneratedCertificate
        {
            CertificatePem = "classical",
            PqcCertificatePem = "pqc",
            SerialNumber = "C1",
            PqcSerialNumber = "C2",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddDays(365)
        }, TestActor, ct);
        await testScope.Service.MarkAsRevokedAsync(created.Id, "superseded", TestActor, ct);

        var all = await testScope.Service.GetAllRevokedForCrlAsync(ct);
        var since = await testScope.Service.GetRevokedSinceForCrlAsync(DateTime.UtcNow.AddDays(-1), ct);

        Assert.Equal("pqc", Assert.Single(all).PqcCertificatePem);
        Assert.Equal("pqc", Assert.Single(since).PqcCertificatePem);
    }

    [Fact]
    public async Task DequeueNextApprovedAsync_DoesNotLeaveTheClaimedRowTracked()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "claim.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        var claimed = await testScope.Service.DequeueNextApprovedAsync(ct);

        Assert.NotNull(claimed);
        Assert.Equal(CertificateRequestStatus.Processing, claimed.Status);
        // ExecuteUpdateAsync writes behind the change tracker, so a tracked row would keep an
        // Approved snapshot while the database says Processing — leaving the hand-patched Status
        // queued as a modification for the next SaveChanges.
        AssertNoPendingModification(testScope.DbContext, claimed);
    }

    [Fact]
    public async Task DequeueNextApprovedAsync_LaterSaveChangesDoesNotResurrectTheClaimedStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "resurrect.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Approved
        }, TestActor, ct);

        await testScope.Service.DequeueNextApprovedAsync(ct);

        // Another worker moves the row on while this scope still holds it.
        await using (var other = NewDbContext(testScope.Connection))
        {
            var row = await other.CertificateRequests.SingleAsync(r => r.Id == created.Id, ct);
            row.Status = CertificateRequestStatus.Rejected;
            await other.SaveChangesAsync(ct);
        }

        // Any unrelated save in the original scope must not write the stale claim back.
        await testScope.DbContext.SaveChangesAsync(ct);

        await using var verify = NewDbContext(testScope.Connection);
        var stored = await verify.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Rejected, stored.Status);
    }

    [Fact]
    public async Task DequeueNextPendingRevocationAsync_DoesNotLeaveTheClaimedRowTracked()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "revoke-claim.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.PendingRevocation
        }, TestActor, ct);

        var claimed = await testScope.Service.DequeueNextPendingRevocationAsync(ct);

        Assert.NotNull(claimed);
        Assert.Equal(CertificateRequestStatus.Revoked, claimed.Status);
        Assert.NotNull(claimed.RevokedAtUtc);
        AssertNoPendingModification(testScope.DbContext, claimed);
    }

    private static void AssertNoPendingModification(CertificateRequestDbContext dbContext, CertificateRequest entity)
    {
        var state = dbContext.Entry(entity).State;
        Assert.True(state is EntityState.Detached or EntityState.Unchanged,
            $"Claimed row must carry no pending modification, but its entry state was {state}.");
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Issued, CertificateRequestStatus.PendingRevocation)]
    [InlineData(CertificateRequestStatus.PendingRevocation, CertificateRequestStatus.Revoked)]
    public async Task UpdateAsync_RevocationTransitions_AreAllowed(
        CertificateRequestStatus from, CertificateRequestStatus to)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = $"transition-{from}-{to}.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = from
        }, TestActor, ct);

        var updated = await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
        {
            CommonName = created.CommonName,
            Status = to
        }, TestActor, ct);

        Assert.NotNull(updated);
        Assert.Equal(to, updated.Status);
    }

    [Fact]
    public async Task UpdateAsync_PendingRevocationToIssued_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var created = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "no-un-revoke.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.PendingRevocation
        }, TestActor, ct);

        // A queued revocation must not be walked back into an issued certificate.
        await Assert.ThrowsAsync<InvalidStateTransitionException>(async () =>
            await testScope.Service.UpdateAsync(created.Id, new CertificateRequest
            {
                CommonName = created.CommonName,
                Status = CertificateRequestStatus.Issued
            }, TestActor, ct));
    }

    [Fact]
    public async Task CreateAsync_ConcurrentDuplicateCommonNames_OnlyOneSucceeds()
    {
        var ct = TestContext.Current.CancellationToken;
        var testScope = await CreateTestScopeAsync();
        var sharedConnection = testScope.Connection;

        // Separate DbContexts against one connection, so the pre-insert check in one can run before
        // another's insert lands. Whichever path catches it — the check or the unique index — the
        // caller must see the same DuplicateRequestException.
        var attempts = Enumerable.Range(0, 5).Select(async _ =>
        {
            var raceDb = NewDbContext(sharedConnection);
            var service = new CertificateRequestService(
                raceDb, new NullAuditLogService(), new NullWebhookService(),
                new Qertum.Services.Policies.IssuancePolicyService(raceDb, new Qertum.Services.Policies.IssuancePolicyEvaluator()));

            try
            {
                await service.CreateAsync(new CertificateRequest
                {
                    CommonName = "race.contoso.local",
                    RequestedBy = "alice@contoso.local"
                }, TestActor, ct);
                return (Created: true, Duplicate: false);
            }
            catch (DuplicateRequestException)
            {
                return (Created: false, Duplicate: true);
            }
        }).ToList();

        var results = await Task.WhenAll(attempts);

        Assert.Single(results, r => r.Created);
        Assert.Equal(4, results.Count(r => r.Duplicate));

        await using var verify = NewDbContext(sharedConnection);
        Assert.Equal(1, await verify.CertificateRequests.CountAsync(r => r.CommonName == "race.contoso.local", ct));

        await testScope.DisposeAsync();
    }

    [Fact]
    public async Task ActiveCommonNameUniqueIndex_IsEnforcedByTheDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "indexed.contoso.local",
            RequestedBy = "alice@contoso.local"
        }, TestActor, ct);

        // Straight insert, bypassing the service's pre-check entirely: the constraint must hold on
        // its own, otherwise the check is the only thing standing between two concurrent creates.
        await using var direct = NewDbContext(testScope.Connection);
        direct.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "indexed.contoso.local",
            RequestedBy = "bob@contoso.local"
        });

        await Assert.ThrowsAnyAsync<DbUpdateException>(async () => await direct.SaveChangesAsync(ct));
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Rejected)]
    [InlineData(CertificateRequestStatus.Revoked)]
    public async Task ActiveCommonNameUniqueIndex_IgnoresTerminalRows(CertificateRequestStatus terminalStatus)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "recycled.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = terminalStatus
        }, TestActor, ct);

        // A rejected or revoked certificate must not reserve its CN forever.
        await using var direct = NewDbContext(testScope.Connection);
        direct.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "recycled.contoso.local",
            RequestedBy = "bob@contoso.local"
        });

        await direct.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task ActiveCommonNameUniqueIndex_ExemptsRenewals()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        var original = await testScope.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "renewable.contoso.local",
            RequestedBy = "alice@contoso.local",
            Status = CertificateRequestStatus.Issued
        }, TestActor, ct);

        // A renewal reuses the CN of a certificate that is still live and valid. RenewAsync inserts
        // without going through the duplicate check, so the index has to carve renewals out too.
        var renewal = await testScope.Service.RenewAsync(original.Id, TestActor, ct);

        Assert.NotNull(renewal);
        Assert.Equal(original.CommonName, renewal.CommonName);
        Assert.Equal(original.Id, renewal.RenewedFromId);
    }

    [Fact]
    public async Task ActiveCommonNameUniqueIndex_ExemptsRootCaRequests()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var testScope = await CreateTestScopeAsync();

        // Root CA requests are unique by type, not by CN, and CreateAsync skips the check for them —
        // the index has to agree or the carve-out stops working.
        await using var direct = NewDbContext(testScope.Connection);
        direct.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "Qertum Root CA",
            RequestedBy = "alice@contoso.local",
            Type = WellKnownCertificateTypes.RootCa
        });
        direct.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "Qertum Root CA",
            RequestedBy = "bob@contoso.local",
            Type = WellKnownCertificateTypes.RootCa
        });

        await direct.SaveChangesAsync(ct);
    }

    private static CertificateRequestDbContext NewDbContext(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

    private static Task<TestScope> CreateTestScopeAsync() =>
        CreateTestScopeAsync(new NullAuditLogService());

    private static async Task<TestScope> CreateTestScopeAsync(IAuditLogService auditLog)
    {
        var ct = TestContext.Current.CancellationToken;
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        var options = new DbContextOptionsBuilder<CertificateRequestDbContext>()
            .UseSqlite(connection)
            .Options;

        var dataProtection = new EphemeralDataProtectionProvider();
        var dbContext = new CertificateRequestDbContext(options, dataProtection);
        await dbContext.Database.EnsureCreatedAsync(ct);
        // The CA default is PQC stage Enforce; these tests issue RSA certificates, so they start from Off.
        dbContext.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
        await dbContext.SaveChangesAsync(ct);

        return new TestScope(connection, dbContext, new CertificateRequestService(dbContext, auditLog, new NullWebhookService(),
            new Qertum.Services.Policies.IssuancePolicyService(dbContext, new Qertum.Services.Policies.IssuancePolicyEvaluator())));
    }

    private sealed class TestScope(
        SqliteConnection connection,
        CertificateRequestDbContext dbContext,
        CertificateRequestService service) : IAsyncDisposable
    {
        public SqliteConnection Connection { get; } = connection;

        public CertificateRequestDbContext DbContext { get; } = dbContext;

        public CertificateRequestService Service { get; } = service;

        public async ValueTask DisposeAsync()
        {
            await DbContext.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}
