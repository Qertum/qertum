using System.Net.Http.Json;
using Qertum.Services;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class CertificateLifecycleTests(AspireIntegrationFixture fixture)
{
    // ── Approve / Reject ───────────────────────────────────────────────────────

    [Fact(DisplayName = "IT-LIFECYCLE-001")]
    public async Task ApprovePendingRequest_Returns200WithApprovedStatus()
    {
        var created = await CreatePendingAsync();

        var resp = await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var result = await resp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Approved, result.Status);
    }

    [Fact(DisplayName = "IT-LIFECYCLE-002")]
    public async Task ApproveAlreadyApprovedRequest_Returns409()
    {
        var created = await CreatePendingAsync();
        await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, TestContext.Current.CancellationToken);

        var second = await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact(DisplayName = "IT-LIFECYCLE-003")]
    public async Task RejectPendingRequest_Returns200WithRejectedStatus()
    {
        var created = await CreatePendingAsync();

        var resp = await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{created.Id}/reject", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var result = await resp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken);
        Assert.NotNull(result);
        Assert.Equal(CertificateRequestStatus.Rejected, result.Status);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<CertificateRequest> CreatePendingAsync()
    {
        var resp = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = TestHelpers.UniqueCN(),
            RequestedBy = "lifecycle-tester",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, TestContext.Current.CancellationToken);
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<CertificateRequest>(TestContext.Current.CancellationToken))!;
    }
}
