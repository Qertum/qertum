using System.Net.Http.Json;
using Qertum.Cli.Commands;
using Qertum.Services;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Aspire;

/// <summary>
/// Bulk renew and bulk revoke through the real stack: ApiService freezes the set, QueueConsumer's
/// <c>BulkOperation</c> job works through it, and the consumer signs and finalizes the revocations.
/// </summary>
[Collection("AspireIntegration")]
public sealed class BulkOperationLifecycleTests(AspireIntegrationFixture fixture)
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(90);

    // The API's rate limiter is one shared window (100 requests a minute for every caller), so this test polls
    // gently; the 500 ms default of PollUntilAsync queues requests behind the limiter when the whole suite runs.
    private static readonly TimeSpan PollEvery = TimeSpan.FromSeconds(2);

    [Fact(DisplayName = "IT-BULK-001")]
    public async Task BulkRenewThenBulkRevoke_WorkEndToEnd()
    {
        var ct = TestContext.Current.CancellationToken;
        var run = Guid.NewGuid().ToString("N")[..12];
        var sources = new List<Guid>();
        for (var i = 0; i < 2; i++)
            sources.Add(await IssueAsync($"bulk-{run}-{i}.local", ct));

        // ── Bulk renew: two new Pending requests, the originals untouched ────────────
        var renewPreview = await PreviewAsync("Renew", run, reason: null, ct);
        Assert.Equal(2, renewPreview.Operation.ItemCount);
        var renewed = await ExecuteAndWaitAsync(renewPreview.Operation.Id, 2, ct);
        Assert.Equal(BulkOperationStatus.Completed, renewed.Status);
        Assert.Equal(2, renewed.DoneCount);

        var items = await fixture.ApiClientAsAdmin.GetFromJsonAsync<PagedResult<BulkOperationItemView>>(
            $"/v1/bulk-operations/{renewed.Id}/items?outcome=Done", ct);
        Assert.Equal(2, items!.TotalCount);
        foreach (var item in items.Items)
        {
            var renewal = await GetRequestAsync((Guid)item.ResultRequestId!.Value, ct);
            Assert.Equal(CertificateRequestStatus.Pending, renewal.Status);
            Assert.Equal(item.RequestId, renewal.RenewedFromId);
            Assert.Equal(CertificateRequestStatus.Issued, (await GetRequestAsync((Guid)item.RequestId, ct)).Status);
        }

        // ── Bulk revoke: the same filter now also matches the two Pending renewals, which are left out ─────
        var revokePreview = await PreviewAsync("Revoke", run, "integration test", ct);
        Assert.Equal(2, revokePreview.Operation.ItemCount);
        Assert.Equal(2, revokePreview.Operation.Excluded["not-issued"]);
        var revoked = await ExecuteAndWaitAsync(revokePreview.Operation.Id, 2, ct);
        Assert.Equal(BulkOperationStatus.Completed, revoked.Status);
        Assert.Equal(2, revoked.DoneCount);

        foreach (var id in sources)
        {
            var final = await TestHelpers.PollUntilAsync(() => GetRequestAsync(id, ct),
                r => r.Status == CertificateRequestStatus.Revoked, Patience, PollEvery);
            Assert.Equal("integration test", final.RevocationReason);
        }
    }

    /// <summary>The <c>qca bulk</c> flows (what the command actions run) against the live API, not a stub.</summary>
    [Fact(DisplayName = "IT-BULK-003")]
    public async Task TheCliFlows_PreviewExecuteAndWait_AgainstTheLiveApi()
    {
        var ct = TestContext.Current.CancellationToken;
        var run = Guid.NewGuid().ToString("N")[..12];
        await IssueAsync($"cli-{run}.local", ct);
        var client = new CertificateRequestsApiClient(fixture.ApiClientAsAdmin);
        var selection = new BulkSelection(null, null, null, null, run, All: false);

        // Preview only: prints the count and the command to run, executes nothing.
        using var previewOut = new StringWriter();
        using var previewErr = new StringWriter();
        var previewExit = await BulkCommands.RunPreviewAsync(client, BulkOperationKind.Renew, selection, null,
            yes: false, confirmCount: null, wait: false, timeoutSeconds: 60, json: false, previewOut, previewErr, ct);
        Assert.Equal(0, previewExit);
        Assert.Contains("items 1", previewOut.ToString());
        Assert.Contains("qca bulk execute", previewOut.ToString());

        // --yes --confirm-count --wait: previews, executes and follows the operation to the end.
        using var runOut = new StringWriter();
        using var runErr = new StringWriter();
        var exit = await BulkCommands.RunPreviewAsync(client, BulkOperationKind.Renew, selection, null,
            yes: true, confirmCount: 1, wait: true, timeoutSeconds: 90, json: false, runOut, runErr, ct);
        Assert.True(exit == 0, $"exit {exit}; out: {runOut}; err: {runErr}");
        Assert.Contains("completed", runOut.ToString());

        // The earlier preview is still only a preview; nothing but the second run filed a renewal.
        var list = await fixture.ApiClientAsAdmin.GetFromJsonAsync<PagedResult<BulkOperationView>>("/v1/bulk-operations?pageSize=200", ct);
        Assert.Contains(list!.Items, o => o.Status == BulkOperationStatus.Previewed && o.Filter.CommonNameContains == run);
        Assert.Contains(list.Items, o => o.Status == BulkOperationStatus.Completed && o.Filter.CommonNameContains == run);
    }

    [Fact(DisplayName = "IT-BULK-002")]
    public async Task AViewer_CannotPreview_AndAnEmptyFilterIsRefused()
    {
        var ct = TestContext.Current.CancellationToken;

        var forbidden = await fixture.ApiClientAsViewer.PostAsJsonAsync("/v1/bulk-operations/preview",
            new { kind = "Renew", filter = new { all = true } }, ct);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var empty = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/bulk-operations/preview",
            new { kind = "Renew", filter = new { } }, ct);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, empty.StatusCode);
    }

    private async Task<Guid> IssueAsync(string commonName, CancellationToken ct)
    {
        var created = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/certificate-requests",
            new { CommonName = commonName, Type = "WebServer", PropertiesJson = "{}" }, ct);
        created.EnsureSuccessStatusCode();
        var request = (await created.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        (await fixture.ApiClientAsAdmin.PostAsync($"/v1/certificate-requests/{request.Id}/approve", null, ct)).EnsureSuccessStatusCode();
        await TestHelpers.PollUntilAsync(() => GetRequestAsync((Guid)request.Id, ct),
            r => r.Status == CertificateRequestStatus.Issued, Patience, PollEvery);
        return request.Id;
    }

    private async Task<CertificateRequest> GetRequestAsync(Guid id, CancellationToken ct) =>
        (await fixture.ApiClientAsAdmin.GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{id}", ct))!;

    private async Task<BulkOperationPreview> PreviewAsync(string kind, string commonNameContains, string? reason, CancellationToken ct)
    {
        var response = await fixture.ApiClientAsAdmin.PostAsJsonAsync("/v1/bulk-operations/preview",
            new { kind, filter = new { commonNameContains }, reason }, ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<BulkOperationPreview>(ct))!;
    }

    private async Task<BulkOperationView> ExecuteAndWaitAsync(BulkOperationId id, int count, CancellationToken ct)
    {
        var started = await fixture.ApiClientAsAdmin.PostAsJsonAsync($"/v1/bulk-operations/{id}/execute", new { confirmCount = count }, ct);
        Assert.Equal(HttpStatusCode.Accepted, started.StatusCode);
        return await TestHelpers.PollUntilAsync(
            async () => (await fixture.ApiClientAsAdmin.GetFromJsonAsync<BulkOperationView>($"/v1/bulk-operations/{id}", ct))!,
            o => o.Status is not (BulkOperationStatus.Previewed or BulkOperationStatus.Running), Patience, PollEvery);
    }
}
