using System.Net.Http.Json;
using Qertum.Services;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class AuditLogTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-AUDIT-001")]
    public async Task CreateRequest_EmitsCreatedAuditEntry()
    {
        var created = await CreatePendingAsync();

        var entries = await GetAuditLogAsync();
        var entry = entries.FirstOrDefault(e => e.Action == "Created" && e.ResourceId == created.Id);
        Assert.NotNull(entry);
        Assert.Equal("qertum-test-m2m", entry.PerformedBy);
        Assert.True(entry.OccurredAtUtc >= DateTime.UtcNow.AddMinutes(-2));
    }

    [Fact(DisplayName = "IT-AUDIT-002")]
    public async Task ApproveRequest_EmitsApprovedAuditEntry()
    {
        var created = await CreatePendingAsync();
        await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, TestContext.Current.CancellationToken);

        var entries = await GetAuditLogAsync();
        var entry = entries.FirstOrDefault(e => e.Action == "Approved" && e.ResourceId == created.Id);
        Assert.NotNull(entry);
    }

    [Fact(DisplayName = "IT-AUDIT-003")]
    public async Task RejectRequest_EmitsRejectedAuditEntry()
    {
        var created = await CreatePendingAsync();
        await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/reject", null, TestContext.Current.CancellationToken);

        var entries = await GetAuditLogAsync();
        var entry = entries.FirstOrDefault(e => e.Action == "Rejected" && e.ResourceId == created.Id);
        Assert.NotNull(entry);
    }

    [Fact(DisplayName = "IT-AUDIT-007")]
    public async Task UpdateSettings_EmitsSettingsUpdatedAuditEntry()
    {
        await fixture.ApiClientAsAdmin.PutAsJsonAsync("/v1/settings", new
        {
            OrganizationName = "AuditTestOrg",
            Country = "US",
            ExpiringSoonDays = 30,
            CertificateValidityDays = 365,
            CrlValidityHours = 24
        }, TestContext.Current.CancellationToken);

        var entries = await GetAuditLogAsync();
        var entry = entries.FirstOrDefault(e => e.Action == "SettingsUpdated");
        Assert.NotNull(entry);
        Assert.Null(entry.ResourceId);
    }

    [Fact(DisplayName = "IT-AUDIT-008")]
    public async Task GetAuditLog_AsViewer_Returns403()
    {
        var response = await fixture.ApiClientAsViewer.GetAsync("/v1/audit-log", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact(DisplayName = "IT-AUDIT-009")]
    public async Task CreatedAuditEntry_HasTraceId()
    {
        var created = await CreatePendingAsync();

        var entries = await GetAuditLogAsync();
        var entry = entries.FirstOrDefault(e => e.Action == "Created" && e.ResourceId == created.Id);
        Assert.NotNull(entry);
        Assert.NotNull(entry.TraceId);
        Assert.Matches("^[0-9a-fA-F]{32}$", entry.TraceId);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<CertificateRequest> CreatePendingAsync()
    {
        var resp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = TestHelpers.UniqueCN(),
            RequestedBy = "audit-tester",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken))!;
    }

    private async Task<List<AuditLogEntry>> GetAuditLogAsync(int pageSize = 500)
    {
        var resp = await fixture.ApiClientAsAdmin.GetAsync($"/v1/audit-log?page=1&pageSize={pageSize}", TestContext.Current.CancellationToken);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<List<AuditLogEntry>>(TestContext.Current.CancellationToken)) ?? [];
    }
}
