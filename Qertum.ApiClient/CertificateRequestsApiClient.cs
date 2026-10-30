using System.Net;
using System.Net.Http.Json;

namespace Qertum.Services;

public sealed class CertificateRequestsApiClient(HttpClient httpClient, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;

    /// <summary>One page of certificates Qertum issued, with both legs of paired requests counted.</summary>
    public async Task<PagedResult<CertificateInventoryItem>> GetCertificateInventoryAsync(
        int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
        await GetJsonAsync<PagedResult<CertificateInventoryItem>>(
            $"v1/certificate-inventory?page={page}&pageSize={pageSize}", cancellationToken)
        ?? new PagedResult<CertificateInventoryItem>();

    /// <summary>One page of expiry and renewal notices, newest first. <paramref name="status"/> and <paramref name="kind"/> are applied by the server.</summary>
    public async Task<PagedResult<NoticeItem>> GetNoticesAsync(
        NoticeStatus? status = null, NoticeKind? kind = null, int page = 1, int pageSize = 50, CancellationToken cancellationToken = default)
    {
        var url = $"v1/notices?page={page}&pageSize={pageSize}";
        if (status is { } s) url += $"&status={s}";
        if (kind is { } k) url += $"&kind={k}";
        return await GetJsonAsync<PagedResult<NoticeItem>>(url, cancellationToken) ?? new PagedResult<NoticeItem>();
    }

    /// <summary>
    /// One page of requests. <paramref name="status"/> and <paramref name="search"/> are applied by
    /// the server, so a caller paging through the result never has to filter a page itself.
    /// </summary>
    public async Task<PagedResult<CertificateRequest>> GetCertificateRequestsAsync(int page = 1, int pageSize = 100,
        CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default)
    {
        var url = $"v1/certificate-requests?page={page}&pageSize={pageSize}{StatusQuery(status)}{SearchQuery(search)}";
        return await GetJsonAsync<PagedResult<CertificateRequest>>(url, cancellationToken)
            ?? new PagedResult<CertificateRequest>();
    }

    /// <summary>Per-status request counts over the same optional search, for the list's filter chips.</summary>
    public async Task<CertificateRequestStatusCounts> GetRequestStatusCountsAsync(string? search = null, CancellationToken cancellationToken = default)
    {
        var url = $"v1/certificate-requests/status-counts?{SearchQuery(search).TrimStart('&')}";
        return await GetJsonAsync<CertificateRequestStatusCounts>(url, cancellationToken)
            ?? new CertificateRequestStatusCounts();
    }

    private static string StatusQuery(CertificateRequestStatus? status) =>
        status is { } s ? $"&status={s}" : string.Empty;

    // Escaped, so a term containing '&' or '+' reaches the server as typed rather than splitting
    // the query string or arriving as a space.
    private static string SearchQuery(string? search) =>
        string.IsNullOrWhiteSpace(search) ? string.Empty : $"&search={Uri.EscapeDataString(search)}";

    public async Task<CertificateRequest?> GetByIdAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/certificate-requests/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    /// <summary>How long to wait between polls when the server gave no usable hint.</summary>
    private static readonly TimeSpan DefaultRetry = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Polls a request until it reaches a final state (Issued, Rejected, Revoked: see
    /// <see cref="CertificateRequestStatusExtensions.IsFinal"/>), the <paramref name="timeout"/> passes, or it
    /// does not exist. Waits between polls as long as the server's <c>Retry-After</c> says, clamped to 1 to 10
    /// seconds, and two seconds when there is none. <paramref name="onUpdate"/> sees every state, including the
    /// last. A failed call throws like any other call; only the timeout is reported as an outcome, and a request
    /// that waits for a person (Pending) simply runs into it.
    /// </summary>
    public async Task<WaitResult> WaitForFinalAsync(CertificateRequestId id, TimeSpan timeout,
        Func<CertificateRequest, Task>? onUpdate = null, CancellationToken cancellationToken = default)
    {
        using var deadline = new CancellationTokenSource(timeout, clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        CertificateRequest? last = null;
        try
        {
            while (true)
            {
                using var response = await httpClient.GetAsync($"v1/certificate-requests/{id}", linked.Token);
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return new WaitResult(WaitOutcome.NotFound, null);

                await response.EnsureSuccessOrThrowAsync(linked.Token);
                last = await response.Content.ReadFromJsonAsync<CertificateRequest>(linked.Token);
                if (last is null)
                    return new WaitResult(WaitOutcome.NotFound, null);

                if (onUpdate is not null)
                    await onUpdate(last);
                if (last.Status.IsFinal())
                    return new WaitResult(WaitOutcome.Final, last);

                await Task.Delay(RetryDelay(response), clock, linked.Token);
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return new WaitResult(WaitOutcome.TimedOut, last);
        }
    }

    private static TimeSpan RetryDelay(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter?.Delta is not { } hint)
            return DefaultRetry;
        return TimeSpan.FromSeconds(Math.Clamp(hint.TotalSeconds, 1, 10));
    }

    /// <summary>
    /// One page of issued certificates. <paramref name="filter"/> and <paramref name="search"/> are
    /// applied by the server, so the caller never filters a fetched page itself.
    /// </summary>
    public async Task<PagedResult<CertificateRequest>> GetIssuedCertificatesAsync(int page = 1, int pageSize = 100,
        IssuedCertificateFilter? filter = null, string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
    {
        var url = $"v1/certificate-requests/issued?page={page}&pageSize={pageSize}"
                + (filter is { } f ? $"&filter={f}" : string.Empty)
                + SearchQuery(search)
                + (validOnly ? "&validOnly=true" : string.Empty);
        return await GetJsonAsync<PagedResult<CertificateRequest>>(url, cancellationToken)
            ?? new PagedResult<CertificateRequest>();
    }

    /// <summary>Certificate counts per validity bucket, for the certificates list's filter chips.</summary>
    public async Task<IssuedCertificateCounts> GetIssuedValidityCountsAsync(string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
    {
        var url = $"v1/certificate-requests/issued/validity-counts?{(SearchQuery(search) + (validOnly ? "&validOnly=true" : string.Empty)).TrimStart('&')}";
        return await GetJsonAsync<IssuedCertificateCounts>(url, cancellationToken)
            ?? new IssuedCertificateCounts();
    }

    public async Task<PagedResult<CertificateRequest>> GetRejectedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<PagedResult<CertificateRequest>>($"v1/certificate-requests/rejected?page={page}&pageSize={pageSize}", cancellationToken)
            ?? new PagedResult<CertificateRequest>();
    }

    public async Task<PagedResult<CertificateRequest>> GetRevokedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<PagedResult<CertificateRequest>>($"v1/certificate-requests/revoked?page={page}&pageSize={pageSize}", cancellationToken)
            ?? new PagedResult<CertificateRequest>();
    }

    public async Task<PagedResult<CertificateRequest>> GetExpiredAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<PagedResult<CertificateRequest>>($"v1/certificate-requests/expired?page={page}&pageSize={pageSize}", cancellationToken)
            ?? new PagedResult<CertificateRequest>();
    }

    /// <summary>Files a request and returns it as created (always <c>Pending</c> over REST).</summary>
    public async Task<CertificateRequest> QueueCertificateRequestAsync(CreateCertificateRequestRequest request, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync("v1/certificate-requests", request, cancellationToken);
        // Policy violations arrive as a problem body listing the rules that refused the request;
        // EnsureSuccessStatusCode would throw all of that away.
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken))!;
    }

    /// <summary>
    /// Asks what would happen if this request were submitted. A rejection comes back as a 200 with
    /// violations, so only a transport or authorization failure throws.
    /// </summary>
    public async Task<CertificateRequestPreviewResponse> PreviewCertificateRequestAsync(
        CreateCertificateRequestRequest request, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync("v1/certificate-requests/preview", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(cancellationToken)
               ?? new CertificateRequestPreviewResponse();
    }

    public async Task<EnrollmentOptionsResponse> GetEnrollmentOptionsAsync(CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync("v1/enrollment/options", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        // An empty body must not read as "no templates configured"; the wizard shows it as unavailable.
        return await response.Content.ReadFromJsonAsync<EnrollmentOptionsResponse>(cancellationToken)
               ?? throw new InvalidOperationException("The enrollment options response was empty.");
    }

    public async Task<CertificateRequest?> ApproveAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/certificate-requests/{id}/approve", null, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    /// <summary>Approves and reports what the approval preview showed; recorded in the audit as client-reported.</summary>
    public async Task<CertificateRequest?> ApproveAsync(CertificateRequestId id, ApproveCertificateRequestRequest report, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync($"v1/certificate-requests/{id}/approve", report, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    /// <summary>
    /// The current policy's verdict on approving a Pending request. A refusal is a 200 with violations;
    /// null when the request does not exist; a non-Pending request throws (409). Each call is audited,
    /// so it is sent once: a retry would record one look as several <c>ApprovalPreviewed</c> entries.
    /// </summary>
    public async Task<ApprovalPreviewResponse?> PreviewApprovalAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"v1/certificate-requests/{id}/approval-preview");
        request.Options.Set(ApiRequestOptions.NoRetryKey, true);
        using var response = await httpClient.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<ApprovalPreviewResponse>(cancellationToken);
    }

    public async Task<CertificateRequest?> RejectAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/certificate-requests/{id}/reject", null, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    public async Task<CertificateRequest?> RevokeAsync(CertificateRequestId id, string? reason, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/certificate-requests/{id}/revoke", new { Reason = reason }, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    /// <summary>Adds a note to a request. The author is taken from the caller's token.</summary>
    public async Task<CertificateNote> AddNoteAsync(Guid requestId, string body, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/certificate-requests/{requestId}/notes", new SaveCertificateNoteRequest { Body = body }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateNote>(cancellationToken))!;
    }

    /// <summary>Replaces the text of the caller's own note.</summary>
    /// <returns>The note, or null when the request or note does not exist.</returns>
    public async Task<CertificateNote?> EditNoteAsync(Guid requestId, NoteId noteId, string body, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-requests/{requestId}/notes/{noteId}", new SaveCertificateNoteRequest { Body = body }, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateNote>(cancellationToken);
    }

    /// <summary>Deletes the caller's own note.</summary>
    /// <returns>False when the request or note does not exist.</returns>
    public async Task<bool> DeleteNoteAsync(Guid requestId, NoteId noteId, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/certificate-requests/{requestId}/notes/{noteId}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return false;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return true;
    }

    /// <summary>
    /// Replaces the metadata set of a request (null fields clear). Allowed for the owner or certificates.manage.
    /// </summary>
    /// <returns>The stored set, or null when no request has that id.</returns>
    public async Task<CertificateMetadata?> UpdateCertificateMetadataAsync(
        CertificateRequestId id, CertificateMetadata metadata, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-requests/{id}/metadata", metadata, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateMetadata>(cancellationToken);
    }

    public async Task<CertificateRequest?> RenewAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/certificate-requests/{id}/renew", null, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken);
    }

    /// <summary>
    /// Previews a bulk revoke or renew: the server resolves <paramref name="request"/>'s filter, freezes the eligible
    /// set and returns the operation with the first few items. Nothing is changed until <see cref="ExecuteBulkOperationAsync"/>.
    /// </summary>
    public async Task<BulkOperationPreview> PreviewBulkOperationAsync(PreviewBulkOperationRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/bulk-operations/preview", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<BulkOperationPreview>(cancellationToken))!;
    }

    /// <summary>Starts a previewed operation. <paramref name="confirmCount"/> must equal the operation's item count.</summary>
    public async Task<BulkOperationView> ExecuteBulkOperationAsync(BulkOperationId id, int confirmCount, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/bulk-operations/{id}/execute", new { ConfirmCount = confirmCount }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<BulkOperationView>(cancellationToken))!;
    }

    /// <summary>Cancels a previewed operation.</summary>
    public async Task<BulkOperationView> CancelBulkOperationAsync(BulkOperationId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/bulk-operations/{id}/cancel", null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<BulkOperationView>(cancellationToken))!;
    }

    /// <summary>One bulk operation, or null when it does not exist or the caller may not see it.</summary>
    public async Task<BulkOperationView?> GetBulkOperationAsync(BulkOperationId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/bulk-operations/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<BulkOperationView>(cancellationToken);
    }

    /// <summary>A page of the caller's bulk operations, newest first (all of them for an admin).</summary>
    public async Task<PagedResult<BulkOperationView>> ListBulkOperationsAsync(int page = 1, int pageSize = 50, CancellationToken cancellationToken = default) =>
        await GetJsonAsync<PagedResult<BulkOperationView>>($"v1/bulk-operations?page={page}&pageSize={pageSize}", cancellationToken)
            ?? new PagedResult<BulkOperationView>();

    /// <summary>A page of one operation's items, optionally only those with <paramref name="outcome"/>.</summary>
    public async Task<PagedResult<BulkOperationItemView>> GetBulkOperationItemsAsync(BulkOperationId id, BulkItemOutcome? outcome = null,
        int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        var filter = outcome is { } o ? $"outcome={o}&" : string.Empty;
        return await GetJsonAsync<PagedResult<BulkOperationItemView>>(
                $"v1/bulk-operations/{id}/items?{filter}page={page}&pageSize={pageSize}", cancellationToken)
            ?? new PagedResult<BulkOperationItemView>();
    }

    /// <summary>
    /// Polls a bulk operation until it is neither <c>Previewed</c> nor <c>Running</c>, the <paramref name="timeout"/>
    /// passes, or it does not exist. Waits as long as the server's <c>Retry-After</c> says, clamped to 1 to 10 seconds,
    /// and two seconds without one. <paramref name="onUpdate"/> sees every state, including the last.
    /// </summary>
    public async Task<BulkWaitResult> WaitForBulkOperationAsync(BulkOperationId id, TimeSpan timeout,
        Func<BulkOperationView, Task>? onUpdate = null, CancellationToken cancellationToken = default)
    {
        using var deadline = new CancellationTokenSource(timeout, clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        BulkOperationView? last = null;
        try
        {
            while (true)
            {
                using var response = await httpClient.GetAsync($"v1/bulk-operations/{id}", linked.Token);
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return new BulkWaitResult(BulkWaitOutcome.NotFound, null);

                await response.EnsureSuccessOrThrowAsync(linked.Token);
                last = await response.Content.ReadFromJsonAsync<BulkOperationView>(linked.Token);
                if (last is null)
                    return new BulkWaitResult(BulkWaitOutcome.NotFound, null);

                if (onUpdate is not null)
                    await onUpdate(last);
                if (last.Status is not (BulkOperationStatus.Previewed or BulkOperationStatus.Running))
                    return new BulkWaitResult(BulkWaitOutcome.Final, last);

                await Task.Delay(RetryDelay(response), clock, linked.Token);
            }
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            return new BulkWaitResult(BulkWaitOutcome.TimedOut, last);
        }
    }

    public async Task<CertificateDashboardSummary> GetDashboardSummaryAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<CertificateDashboardSummary>("v1/certificate-requests/summary", cancellationToken)
            ?? new CertificateDashboardSummary();
    }

    /// <summary>
    /// Conditions that currently need attention, limited to what the caller may see. Throws
    /// <see cref="ApiProblemException"/> on failure — callers must show that as "unavailable",
    /// never as all clear.
    /// </summary>
    public async Task<AttentionReport> GetAttentionAsync(CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync("v1/dashboard/attention", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<AttentionReport>(cancellationToken)
               ?? new AttentionReport();
    }

    /// <summary>
    /// What the host's backup and restore scripts last reported, judged against the configured limits.
    /// Throws <see cref="ApiProblemException"/> on failure — callers must show that as "unavailable".
    /// </summary>
    public async Task<RecoveryStatus> GetRecoveryStatusAsync(CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync("v1/recovery-status", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<RecoveryStatus>(cancellationToken)
               ?? new RecoveryStatus();
    }

    /// <summary>The history of one certificate request, with withheld sections listed.</summary>
    public async Task<CertificateTimelineResponse> GetTimelineAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync($"v1/certificate-requests/{id}/timeline", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateTimelineResponse>(cancellationToken)
               ?? new CertificateTimelineResponse();
    }

    /// <summary>ACME orders, newest first; <paramref name="failingOnly"/> keeps orders with a failed attempt or an invalid status.</summary>
    public async Task<PagedResult<AcmeOrderSummary>> GetAcmeOrdersAsync(string? search, bool failingOnly, int page, int pageSize,
        CancellationToken cancellationToken = default)
    {
        var query = $"v1/acme/orders?page={page}&pageSize={pageSize}&failing={(failingOnly ? "true" : "false")}";
        if (!string.IsNullOrWhiteSpace(search)) query += $"&search={Uri.EscapeDataString(search)}";
        return await GetJsonAsync<PagedResult<AcmeOrderSummary>>(query, cancellationToken)
               ?? new PagedResult<AcmeOrderSummary>();
    }

    /// <summary>An EST credential's refusals and enrollments, newest first; null when there is no such credential.</summary>
    public async Task<PagedResult<TimelineEntry>?> GetEstCredentialActivityAsync(Guid id, int page, int pageSize,
        CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(
            $"v1/est/enrollment-credentials/{id}/activity?page={page}&pageSize={pageSize}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<PagedResult<TimelineEntry>>(cancellationToken);
    }

    /// <summary>One ACME order with its authorizations and diagnostic history; null when there is no such order.</summary>
    public async Task<AcmeOrderDetail?> GetAcmeOrderAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync($"v1/acme/orders/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<AcmeOrderDetail>(cancellationToken);
    }

    public async Task<CaSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<CaSettings>("v1/settings", cancellationToken)
            ?? new CaSettings();
    }

    public async Task<CaSettings> SetupOrUpdateSettingsAsync(CaSettings settings, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings", settings, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);

        return await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken: cancellationToken)
            ?? new CaSettings();
    }

    public async Task<IReadOnlyList<AuditLogEntry>> GetAuditLogAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<List<AuditLogEntry>>($"v1/audit-log?page={page}&pageSize={pageSize}", cancellationToken)
            ?? [];
    }

    /// <summary>Gets the head of every audit hash chain now (admin only). Keep it off-host as the anchor for <c>qca audit verify</c>.</summary>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<AuditCheckpoint> GetAuditCheckpointAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<AuditCheckpoint>("v1/audit-log/checkpoint", cancellationToken)
            ?? new AuditCheckpoint();
    }

    public async Task<SecretStorageStatusResponse> GetSecretStorageStatusAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<SecretStorageStatusResponse>("v1/secret-storage/status", cancellationToken)
            ?? new SecretStorageStatusResponse("Unknown", false);
    }

    public async Task MigrateSecretStorageAsync(string targetProvider, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync(
            "v1/secret-storage/migrate", new MigrateSecretStorageRequest(targetProvider), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    public async Task<CrlBaseResetResponse> ResetCrlBaseAsync(CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync("v1/crl/reset-base", content: null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);

        return await response.Content.ReadFromJsonAsync<CrlBaseResetResponse>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Reset-base response body was empty.");
    }

    public async Task<IReadOnlyList<CertificateTemplate>> GetCertificateTemplatesAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<List<CertificateTemplate>>("v1/certificate-templates", cancellationToken)
            ?? [];
    }

    public async Task<CertificateTemplate?> GetCertificateTemplateByIdAsync(CertificateTemplateId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/certificate-templates/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken);
    }

    public async Task<CertificateTemplate> CreateCertificateTemplateAsync(SaveCertificateTemplateRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/certificate-templates", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken))!;
    }

    public async Task<CertificateTemplate> UpdateCertificateTemplateAsync(CertificateTemplateId id, SaveCertificateTemplateRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-templates/{id}", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken))!;
    }

    public async Task DeleteCertificateTemplateAsync(CertificateTemplateId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/certificate-templates/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>Every issuance policy, by name. Archived policies are included; the page filters them.</summary>
    public async Task<IReadOnlyList<IssuancePolicySummaryResponse>> GetIssuancePoliciesAsync(CancellationToken cancellationToken = default)
        => await GetJsonAsync<List<IssuancePolicySummaryResponse>>(
               "v1/issuance-policies", cancellationToken) ?? [];

    /// <summary>One policy with its published and draft versions, or null when it does not exist.</summary>
    public async Task<IssuancePolicyResponse?> GetIssuancePolicyAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/issuance-policies/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<IssuancePolicyResponse>(cancellationToken);
    }

    /// <summary>Every version of a policy, newest first.</summary>
    public async Task<IReadOnlyList<IssuancePolicyVersionResponse>> GetIssuancePolicyVersionsAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
        => await GetJsonAsync<List<IssuancePolicyVersionResponse>>(
               $"v1/issuance-policies/{id}/versions", cancellationToken) ?? [];

    /// <summary>Creates a policy. The policy starts with no published version, so it governs nothing yet.</summary>
    public async Task<IssuancePolicyResponse> CreateIssuancePolicyAsync(SaveIssuancePolicyRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/issuance-policies", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuancePolicyResponse>(cancellationToken))!;
    }

    /// <summary>Renames a policy or changes its description. The CLI's <c>policies update</c> uses it.</summary>
    public async Task<IssuancePolicyResponse> UpdateIssuancePolicyAsync(IssuancePolicyId id, SaveIssuancePolicyRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/issuance-policies/{id}", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuancePolicyResponse>(cancellationToken))!;
    }

    /// <summary>Creates or replaces the policy's draft rules.</summary>
    public async Task<IssuancePolicyResponse> SaveIssuancePolicyDraftAsync(IssuancePolicyId id, SaveIssuancePolicyDraftRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/issuance-policies/{id}/draft", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuancePolicyResponse>(cancellationToken))!;
    }

    /// <summary>Discards the policy's draft.</summary>
    public async Task DiscardIssuancePolicyDraftAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/issuance-policies/{id}/draft", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>
    /// Publishes the draft the caller reviewed. The id and timestamp are the concurrency token: a
    /// draft edited since is a 409, so nobody publishes rules they never saw.
    /// </summary>
    public async Task<IssuancePolicyResponse> PublishIssuancePolicyAsync(IssuancePolicyId id, PublishIssuancePolicyRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/issuance-policies/{id}/publish", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuancePolicyResponse>(cancellationToken))!;
    }

    /// <summary>Archives a policy, refused while a template still links to it.</summary>
    public async Task ArchiveIssuancePolicyAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/issuance-policies/{id}/archive", null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>Returns an archived policy to use.</summary>
    public async Task UnarchiveIssuancePolicyAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/issuance-policies/{id}/unarchive", null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>Deletes a policy, refused unless no template links to it and no request records one of its versions.</summary>
    public async Task DeleteIssuancePolicyAsync(IssuancePolicyId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/issuance-policies/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>Points a template at a policy, or unlinks it with null. Needs <c>policies.publish</c>.</summary>
    public async Task<CertificateTemplate> SetTemplateIssuancePolicyAsync(CertificateTemplateId id, IssuancePolicyId? policyId, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-templates/{id}/issuance-policy",
            new SetTemplateIssuancePolicyRequest { IssuancePolicyId = policyId }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken))!;
    }

    public async Task<CertificateTemplate> SetTemplateIssuerAsync(CertificateTemplateId id, IssuerId? issuerId, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-templates/{id}/issuer",
            new SetTemplateIssuerRequest { IssuerId = issuerId }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken))!;
    }

    /// <summary>
    /// The PQC migration report: what a stage would do to live certificates and in-flight requests.
    /// Needs certificates.view; the observed-traffic block also needs settings.edit and is otherwise withheld.
    /// Throws <see cref="ApiProblemException"/> for an unknown template or a bad parameter (GetJsonAsync would turn a 404 into null).
    /// </summary>
    public async Task<PqcMigrationReportResponse> GetPqcMigrationReportAsync(PqcReportQuery query, CancellationToken cancellationToken = default)
    {
        var parameters = new List<string>
        {
            $"observedDays={query.ObservedDays}", $"page={query.Page}", $"pageSize={query.PageSize}"
        };
        if (query.TemplateTypeKey is { } template) parameters.Add($"template={Uri.EscapeDataString(template)}");
        if (query.ProposedStage is { } stage) parameters.Add($"proposedStage={stage}");

        var response = await httpClient.GetAsync($"v1/pqc/migration-report?{string.Join('&', parameters)}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<PqcMigrationReportResponse>(cancellationToken))!;
    }

    /// <summary>Sets the CA-wide default PQC stage. Admin only.</summary>
    public async Task<CaSettings> SetPqcStageAsync(PqcStage stage, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings/pqc-stage",
            new SetPqcStageRequest { Stage = stage }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken))!;
    }

    /// <summary>Sets what happens when a certificate's key claims a higher NIST level than its issuer's. Admin only.</summary>
    public async Task<CaSettings> SetIssuerStrengthAsync(IssuerStrengthMode mode, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings/issuer-strength",
            new SetIssuerStrengthRequest { Mode = mode }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken))!;
    }

    /// <summary>Sets what happens when an issuer's own certificate is revoked. Admin only.</summary>
    public async Task<CaSettings> SetRevokedIssuerModeAsync(RevokedIssuerMode mode, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings/revoked-issuer",
            new SetRevokedIssuerModeRequest { Mode = mode }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken))!;
    }

    /// <summary>Sets whether a CA-capable request needs a different approver than its requester. Admin only.</summary>
    public async Task<CaSettings> SetCaApprovalRuleAsync(bool requireIndependent, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings/ca-approval",
            new SetCaApprovalRequest { RequireIndependentApproval = requireIndependent }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken))!;
    }

    /// <summary>Turns two-person approval of sensitive operations on or off. Admin only.</summary>
    public async Task<CaSettings> SetTwoPersonApprovalAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync("v1/settings/two-person-approval",
            new SetTwoPersonApprovalRequest { Enabled = enabled }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaSettings>(cancellationToken))!;
    }

    /// <summary>Asks for a second administrator's approval of a sensitive operation.</summary>
    public async Task<ApprovalResponse> RequestApprovalAsync(RequestApprovalRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/approvals", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<ApprovalResponse>(cancellationToken))!;
    }

    /// <summary>One page of approval requests: all of them for an administrator (unless <paramref name="mine"/>), otherwise the caller's own.</summary>
    public async Task<PagedResult<ApprovalResponse>> GetApprovalsAsync(
        ApprovalStatus? status = null, bool mine = false, int page = 1, int pageSize = 50, CancellationToken cancellationToken = default)
    {
        var url = $"v1/approvals?page={page}&pageSize={pageSize}";
        if (status is { } s) url += $"&status={s}";
        if (mine) url += "&mine=true";
        return await GetJsonAsync<PagedResult<ApprovalResponse>>(url, cancellationToken) ?? new PagedResult<ApprovalResponse>();
    }

    /// <summary>One approval request; the caller's own, or any for an administrator.</summary>
    public async Task<ApprovalResponse> GetApprovalAsync(ApprovalRequestId id, CancellationToken cancellationToken = default) =>
        (await GetJsonAsync<ApprovalResponse>($"v1/approvals/{id}", cancellationToken))!;

    /// <summary>Approves or denies a pending approval request. Administrators only, never the requester.</summary>
    public async Task<ApprovalResponse> DecideApprovalAsync(ApprovalRequestId id, bool approve, string? note, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/approvals/{id}/{(approve ? "approve" : "deny")}",
            new DecideApprovalRequest(note), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<ApprovalResponse>(cancellationToken))!;
    }

    /// <summary>Sets or clears (null) a template's PQC stage override. Admin only.</summary>
    public async Task<CertificateTemplate> SetTemplatePqcStageAsync(CertificateTemplateId id, PqcStage? stage, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/certificate-templates/{id}/pqc-stage",
            new SetTemplatePqcStageRequest { Stage = stage }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateTemplate>(cancellationToken))!;
    }

    /// <summary>Lists PQC exceptions; only the active ones unless <paramref name="includeInactive"/>. Admin only.</summary>
    public async Task<IReadOnlyList<PqcExceptionResponse>> GetPqcExceptionsAsync(bool includeInactive, CancellationToken cancellationToken = default) =>
        await GetJsonAsync<List<PqcExceptionResponse>>(
            $"v1/pqc-exceptions?includeInactive={includeInactive.ToString().ToLowerInvariant()}", cancellationToken) ?? [];

    /// <summary>Grants a PQC exception. Admin only.</summary>
    public async Task<PqcExceptionResponse> CreatePqcExceptionAsync(CreatePqcExceptionRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/pqc-exceptions", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<PqcExceptionResponse>(cancellationToken))!;
    }

    /// <summary>Revokes a PQC exception. Admin only.</summary>
    public async Task<PqcExceptionResponse> RevokePqcExceptionAsync(PqcExceptionId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsync($"v1/pqc-exceptions/{id}/revoke", null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<PqcExceptionResponse>(cancellationToken))!;
    }

    public async Task<CaStatusResponse> GetCaStatusAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<CaStatusResponse>("v1/ca/status", cancellationToken)
            ?? new CaStatusResponse { IsInitialized = true };
    }

    public async Task<CertificateRequest> GenerateCaAsync(GenerateCaRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/ca/generate", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CertificateRequest>(cancellationToken))!;
    }

    public async Task<CaStatusResponse> ImportCaAsync(ImportCaRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/ca/import", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CaStatusResponse>(cancellationToken))!;
    }

    /// <summary>
    /// Downloads the PEM private key of an issued certificate. Returns null when the caller does not
    /// own the certificate, when it is not issued, or when no key is held server-side (ACME requests).
    /// </summary>
    public async Task<byte[]?> DownloadPrivateKeyAsync(CertificateRequestId id, bool pqc = false, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/certificate-requests/{id}/private-key?pqc={(pqc ? "true" : "false")}", cancellationToken);
        if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
            return null;

        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    /// <summary>
    /// Exports an issued certificate and its private key as PKCS#12. Returns null under the same
    /// conditions as <see cref="DownloadPrivateKeyAsync"/>.
    /// </summary>
    public async Task<byte[]?> DownloadPfxAsync(CertificateRequestId id, string? password, bool pqc = false, bool includeChain = true, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync(
            $"v1/certificate-requests/{id}/pfx",
            new ExportPfxRequest(password, pqc, includeChain),
            cancellationToken);

        if (response.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
            return null;

        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    public async Task<byte[]> DownloadCaCertificateAsync(string format = "pem", CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync($"v1/ca/certificate?format={format}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    /// <summary>Every issuer, or with <paramref name="validOnly"/> only those whose certificate chain can still be used.</summary>
    public async Task<IReadOnlyList<IssuerResponse>> GetIssuersAsync(bool validOnly = false, CancellationToken cancellationToken = default) =>
        await GetJsonAsync<List<IssuerResponse>>(validOnly ? "v1/issuers?validOnly=true" : "v1/issuers", cancellationToken) ?? [];

    public Task<IssuerResponse?> GetIssuerAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        GetJsonAsync<IssuerResponse>($"v1/issuers/{id}", cancellationToken);

    public Task<byte[]> DownloadIssuerCertificateAsync(IssuerId id, string format = "pem", CancellationToken cancellationToken = default) =>
        GetBytesAsync($"v1/issuers/{id}/certificate?format={format}", cancellationToken);

    public Task<byte[]> DownloadIssuerChainAsync(IssuerId id, string format = "pem", CancellationToken cancellationToken = default) =>
        GetBytesAsync($"v1/issuers/{id}/chain?format={format}", cancellationToken);

    /// <summary>An online issuer's private key as PEM. Administrators only; throws when this server holds no key for it.</summary>
    public Task<byte[]> DownloadIssuerPrivateKeyAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        GetBytesAsync($"v1/issuers/{id}/private-key", cancellationToken);

    /// <summary>An online issuer's certificate and private key as PKCS#12. Administrators only; throws when this server holds no key for it.</summary>
    public async Task<byte[]> DownloadIssuerPfxAsync(IssuerId id, string? password, bool includeChain = true, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/issuers/{id}/pfx", new ExportIssuerPfxRequest(password, includeChain), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    public Task<byte[]> DownloadTrustBundleAsync(string format = "pem", CancellationToken cancellationToken = default) =>
        GetBytesAsync($"v1/issuers/trust-bundle?format={format}", cancellationToken);

    /// <summary>
    /// Renews an intermediate with a new key under the same name. <c>RequestFile</c> is null when it was signed at
    /// once (the replacement is already active); otherwise the replacement waits for the parent's signature.
    /// </summary>
    public async Task<CreateIntermediateResponse> RenewIssuerAsync(IssuerId id, int? validityDays = null, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/issuers/{id}/renew", new RenewIssuerRequest(validityDays), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(cancellationToken))!;
    }

    public async Task<CreateIntermediateResponse> CreateIntermediateAsync(CreateIntermediateRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/issuers/intermediates", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(cancellationToken))!;
    }

    public async Task<IntermediateRequestFile> GetIntermediateRequestFileAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        await GetJsonAsync<IntermediateRequestFile>($"v1/issuers/{id}/request", cancellationToken)
        ?? throw new InvalidOperationException("The issuer has no request file.");

    public async Task<IssuerResponse> InstallIssuerCertificateAsync(IssuerId id, InstallIssuerCertificateRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync($"v1/issuers/{id}/certificate", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuerResponse>(cancellationToken))!;
    }

    public async Task<IssuerResponse> UploadIssuerCrlAsync(IssuerId id, byte[] crl, CancellationToken cancellationToken = default)
    {
        using var content = new ByteArrayContent(crl);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pkix-crl");
        var response = await httpClient.PostAsync($"v1/issuers/{id}/crl", content, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuerResponse>(cancellationToken))!;
    }

    public async Task DeleteIssuerAsync(IssuerId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/issuers/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    public Task<IssuerResponse> MakeIssuerDefaultAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        PostIssuerActionAsync(id, "make-default", cancellationToken);

    public Task<IssuerResponse> RetireIssuerAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        PostIssuerActionAsync(id, "retire", cancellationToken);

    public Task<IssuerResponse> ArchiveIssuerAsync(IssuerId id, CancellationToken cancellationToken = default) =>
        PostIssuerActionAsync(id, "archive", cancellationToken);

    private async Task<IssuerResponse> PostIssuerActionAsync(IssuerId id, string action, CancellationToken cancellationToken)
    {
        var response = await httpClient.PostAsync($"v1/issuers/{id}/{action}", content: null, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<IssuerResponse>(cancellationToken))!;
    }

    private async Task<byte[]> GetBytesAsync(string url, CancellationToken cancellationToken)
    {
        var response = await httpClient.GetAsync(url, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Webhook>> GetWebhooksAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<List<Webhook>>("v1/webhooks", cancellationToken) ?? [];
    }

    /// <summary>One webhook, or null when it does not exist.</summary>
    public async Task<Webhook?> GetWebhookAsync(WebhookId id, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync($"v1/webhooks/{id}", cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<Webhook>(cancellationToken);
    }

    public async Task<Webhook> CreateWebhookAsync(SaveWebhookRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/webhooks", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<Webhook>(cancellationToken))!;
    }

    public async Task<Webhook> UpdateWebhookAsync(WebhookId id, SaveWebhookRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync($"v1/webhooks/{id}", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<Webhook>(cancellationToken))!;
    }

    public async Task DeleteWebhookAsync(WebhookId id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/webhooks/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    /// <summary>Reads the administrator's effective webhook destination policy.</summary>
    public async Task<WebhookDestinationPolicyResponse> GetWebhookDestinationPolicyAsync(CancellationToken cancellationToken = default)
        => await GetJsonAsync<WebhookDestinationPolicyResponse>("v1/webhook-destinations", cancellationToken)
           ?? throw new InvalidOperationException("The webhook destination policy response was empty.");

    /// <summary>Sets the public mode; null restores the JSON configuration default.</summary>
    public async Task<WebhookDestinationPolicyResponse> SetWebhookDestinationPublicModeAsync(
        WebhookPublicMode? mode, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PutAsJsonAsync("v1/webhook-destinations/mode",
            new SetWebhookDestinationModeRequest { PublicMode = mode }, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<WebhookDestinationPolicyResponse>(cancellationToken))!;
    }

    /// <summary>Adds an administrator-owned exact-origin destination rule.</summary>
    public async Task<WebhookDestinationRuleResponse> AddWebhookDestinationRuleAsync(
        SaveWebhookDestinationRuleRequest request, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PostAsJsonAsync("v1/webhook-destinations/rules", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<WebhookDestinationRuleResponse>(cancellationToken))!;
    }

    /// <summary>Changes a destination rule's enabled state; null means the rule was absent.</summary>
    public async Task<WebhookDestinationRuleResponse?> SetWebhookDestinationRuleEnabledAsync(
        Guid id, bool enabled, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.PutAsJsonAsync($"v1/webhook-destinations/rules/{id}/enabled",
            new SetWebhookDestinationRuleEnabledRequest { Enabled = enabled }, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<WebhookDestinationRuleResponse>(cancellationToken);
    }

    /// <summary>Deletes an administrator-owned destination rule.</summary>
    public async Task DeleteWebhookDestinationRuleAsync(Guid id, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.DeleteAsync($"v1/webhook-destinations/rules/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AcmeExternalAccountKeyResponse>> GetAcmeExternalAccountKeysAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<List<AcmeExternalAccountKeyResponse>>(
            "v1/acme/external-account-keys", cancellationToken) ?? [];
    }

    /// <summary>
    /// Issues a credential. The MAC key comes back only in this response — it is stored encrypted and
    /// no endpoint reads it back, so it has to be handed to its holder now.
    /// </summary>
    public async Task<AcmeExternalAccountKeyCreatedResponse> CreateAcmeExternalAccountKeyAsync(
        CreateAcmeExternalAccountKeyRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/acme/external-account-keys", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<AcmeExternalAccountKeyCreatedResponse>(cancellationToken))!;
    }

    public async Task<AcmeExternalAccountKeyResponse?> SetAcmeExternalAccountKeyEnabledAsync(
        Guid id, bool isEnabled, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync(
            $"v1/acme/external-account-keys/{id}", new UpdateAcmeExternalAccountKeyRequest(isEnabled), cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<AcmeExternalAccountKeyResponse>(cancellationToken);
    }

    public async Task DeleteAcmeExternalAccountKeyAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/acme/external-account-keys/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<EstEnrollmentCredentialResponse>> GetEstEnrollmentCredentialsAsync(CancellationToken cancellationToken = default)
    {
        return await GetJsonAsync<List<EstEnrollmentCredentialResponse>>(
            "v1/est/enrollment-credentials", cancellationToken) ?? [];
    }

    /// <summary>
    /// Issues a credential. The password comes back only in this response — it is stored hashed and
    /// no endpoint reads it back, so it has to be handed to its holder now.
    /// </summary>
    public async Task<EstEnrollmentCredentialCreatedResponse> CreateEstEnrollmentCredentialAsync(
        CreateEstEnrollmentCredentialRequest request, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync("v1/est/enrollment-credentials", request, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<EstEnrollmentCredentialCreatedResponse>(cancellationToken))!;
    }

    public async Task<EstEnrollmentCredentialResponse?> SetEstEnrollmentCredentialEnabledAsync(
        Guid id, bool isEnabled, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync(
            $"v1/est/enrollment-credentials/{id}", new UpdateEstEnrollmentCredentialRequest(isEnabled), cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<EstEnrollmentCredentialResponse>(cancellationToken);
    }

    public async Task DeleteEstEnrollmentCredentialAsync(Guid id, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.DeleteAsync($"v1/est/enrollment-credentials/{id}", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
    }

    public async Task<RolePermissionsOverviewResponse> GetRolePermissionsOverviewAsync(CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync("v1/permissions/overview", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<RolePermissionsOverviewResponse>(cancellationToken))!;
    }

    public async Task<RolePermissionChange> SetRolePermissionsAsync(string role, IReadOnlyList<string> permissions, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PutAsJsonAsync(
            $"v1/permissions/{Uri.EscapeDataString(role)}", new SetRolePermissionsRequest(permissions), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<RolePermissionChange>(cancellationToken))!;
    }

    public async Task<MyAccessResponse> GetMyAccessAsync(CancellationToken cancellationToken = default)
    {
        var response = await httpClient.GetAsync("v1/me/access", cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<MyAccessResponse>(cancellationToken))!;
    }

    public async Task<RoleRenameResponse> RenameRoleAsync(string role, string newRole, CancellationToken cancellationToken = default)
    {
        var response = await httpClient.PostAsJsonAsync(
            $"v1/permissions/{Uri.EscapeDataString(role)}/rename", new RenameRoleRequest(newRole), cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return (await response.Content.ReadFromJsonAsync<RoleRenameResponse>(cancellationToken))!;
    }

    // Every read fails the same way as every write: an ApiProblemException carrying the server's
    // title and detail. GetFromJsonAsync would throw an HttpRequestException with neither.
    private async Task<T?> GetJsonAsync<T>(string url, CancellationToken cancellationToken)
    {
        using var response = await httpClient.GetAsync(url, cancellationToken);
        await response.EnsureSuccessOrThrowAsync(cancellationToken);
        return await response.Content.ReadFromJsonAsync<T>(cancellationToken);
    }
}

/// <summary>How <see cref="CertificateRequestsApiClient.WaitForFinalAsync"/> ended.</summary>
public enum WaitOutcome
{
    /// <summary>The request reached Issued, Rejected or Revoked.</summary>
    Final,

    /// <summary>The timeout passed while it was still on its way (or waiting for a person).</summary>
    TimedOut,

    /// <summary>No such request.</summary>
    NotFound
}

/// <summary>The outcome, and the last state seen (null when the request does not exist).</summary>
public sealed record WaitResult(WaitOutcome Outcome, CertificateRequest? Request);

/// <summary>How <see cref="CertificateRequestsApiClient.WaitForBulkOperationAsync"/> ended.</summary>
public enum BulkWaitOutcome
{
    /// <summary>The operation left <c>Previewed</c> and <c>Running</c>: it completed, completed with errors, was cancelled or expired.</summary>
    Final,

    /// <summary>The timeout passed while it was still previewed or running.</summary>
    TimedOut,

    /// <summary>No such operation, or the caller may not see it.</summary>
    NotFound
}

/// <summary>The outcome, and the last state seen (null when the operation does not exist).</summary>
public sealed record BulkWaitResult(BulkWaitOutcome Outcome, BulkOperationView? Operation);
