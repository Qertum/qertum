using Qertum.Services.CertificateNotes;
using Qertum.Services.Notices;
using Qertum.Services.Approvals;
using Qertum.Services.BulkOperations;
using Qertum.Services.Issuers;
using System.Security.Cryptography.X509Certificates;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Qertum.Services.Auth;

using Qertum.Services.Webhooks;

using Qertum.Services.Crypto;

namespace Qertum.Services;

public static class ApiEndpointMappings
{
    private const string CrlCacheKey = CrlCache.Key;
    private const string CrlCacheDeltaKey = CrlCache.DeltaKey;
    private const string OcspResponseContentType = "application/ocsp-response";

    /// <summary>Resolves the calling identity, including its CA permission, for policy evaluation.</summary>
    private static Task<Policies.CallerContext> CallerOf(
        HttpContext httpContext, IIdentityClaimsMapper claimsMapper, Policies.ICallerContextResolver resolver, CancellationToken ct) =>
        resolver.ResolveAsync(claimsMapper.GetSubject(httpContext.User), claimsMapper.GetName(httpContext.User),
            [.. claimsMapper.GetRoles(httpContext.User)], ct);

    /// <summary>
    /// Reduces a common name to a filename-safe token. A CN is user-supplied and reaches the
    /// Content-Disposition header, so separators and control characters must not survive.
    /// </summary>
    internal static string SafeFileName(string commonName)
    {
        if (string.IsNullOrWhiteSpace(commonName))
            return "certificate";

        var cleaned = new string(commonName
            .Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_')
            .ToArray())
            .Trim('.', '_');

        return string.IsNullOrEmpty(cleaned) ? "certificate" : cleaned;
    }

    public static IEndpointRouteBuilder MapCustomCaApi(this IEndpointRouteBuilder endpoints)
    {
        // All versioned API routes live under /v1/. Versioning is by route prefix alone: there is
        // no versioning library in play, so a future /v2/ is a second MapGroup here rather than
        // version metadata on each endpoint. Clients on /v1/ keep working when it lands.
        var v1 = endpoints.MapGroup("/v1");

        v1.MapGet("/certificate-inventory", async (
            CertificateInventoryService inventory, int page = 1, int pageSize = 100,
            CancellationToken cancellationToken = default) =>
            Results.Ok(await inventory.GetAsync(page, pageSize, cancellationToken)))
            .WithTags("Certificate Inventory")
            .RequireAuthorization(AppPermissions.CertificatesView)
            .RequireRateLimiting("api");

        // Caller's roles as the API maps them, with every permission and whether it is held.
        v1.MapGet("/me/access", async (IRoleAccessService access, HttpContext httpContext,
            IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
            Results.Ok(await access.GetMyAccessAsync(
                claimsMapper.GetRoles(httpContext.User), claimsMapper.IsAdmin(httpContext.User), cancellationToken)))
            .RequireAuthorization();

        // Dashboard attention view — any authenticated caller. The route grants nothing by itself:
        // each check is gated on the permission that already guards its data, resolved here because
        // the permission policies only succeed with the HttpContext as the authorization resource.
        v1.MapGet("/dashboard/attention", async (
            Dashboard.IAttentionService attention, IAuthorizationService authorization,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var access = new Dashboard.AttentionAccess(
                CanViewCertificates: (await authorization.AuthorizeAsync(httpContext.User, httpContext, AppPermissions.CertificatesView)).Succeeded,
                CanEditSettings: (await authorization.AuthorizeAsync(httpContext.User, httpContext, AppPermissions.SettingsEdit)).Succeeded,
                IsAdmin: claimsMapper.IsAdmin(httpContext.User),
                Subject: claimsMapper.GetSubject(httpContext.User));
            return Results.Ok(await attention.GetReportAsync(access, cancellationToken));
        }).WithTags("Dashboard").RequireAuthorization().RequireRateLimiting("api");

        // What the host's backup and restore scripts last reported — settings.edit. Reported, not
        // verified: the files are written outside Qertum, so the response says who claimed what.
        v1.MapGet("/recovery-status", async (Recovery.IRecoveryStatusService recovery, CancellationToken cancellationToken) =>
            Results.Ok(await recovery.GetAsync(cancellationToken)))
            .WithTags("Recovery")
            .RequireAuthorization(AppPermissions.SettingsEdit)
            .RequireRateLimiting("api");

        // Enrollment wizard options — certificates.create. Read-only allowlist: templates, purposes and
        // the enrollment facts a requester needs, without granting certificates.view or settings.edit.
        // Filtered by the caller's roles with the same test create applies, so the wizard never
        // offers a template the create would refuse.
        v1.MapGet("/enrollment/options", async (Enrollment.IEnrollmentOptionsService enrollment,
                HttpContext httpContext, IIdentityClaimsMapper claimsMapper, Policies.ICallerContextResolver callerResolver,
                CancellationToken cancellationToken) =>
            {
                // Always non-null: a null caller would silently skip the CA-permission filter.
                var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
                return Results.Ok(await enrollment.GetAsync(
                    Policies.RequesterRoles.From(claimsMapper.GetRoles(httpContext.User)), caller, cancellationToken));
            })
            .WithTags("Enrollment")
            .RequireAuthorization(AppPermissions.CertificatesCreate)
            .RequireRateLimiting("api");

        // Role permission management — admin role only. A grantable permission for managing grants
        // would let its holder grant itself anything, policies.publish included.
        var permissionsGroup = v1.MapGroup("/permissions").RequireAuthorization("admin-role");

        permissionsGroup.MapGet("/", async (RolePermissionsApiService svc, CancellationToken cancellationToken) =>
            Results.Ok(await svc.GetAllAsync(cancellationToken)));

        permissionsGroup.MapGet("/overview", async (IRoleAccessService access, CancellationToken cancellationToken) =>
            Results.Ok(await access.GetOverviewAsync(cancellationToken)));

        permissionsGroup.MapPut("/{role}", async (
            string role, SetRolePermissionsRequest request, RolePermissionsApiService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            if (!RoleNameRules.TryValidate(role, out var roleError))
                return Results.Problem(title: "Invalid role name", detail: roleError, statusCode: 400);

            if (string.Equals(role, AppRoles.Admin, StringComparison.OrdinalIgnoreCase))
                return Results.Problem(title: "Admin role permissions cannot be modified.", statusCode: 400);

            var requested = request.Permissions ?? [];
            var unknown = requested.Where(p => !AppPermissions.All.Contains(p)).Distinct(StringComparer.Ordinal).ToList();
            if (unknown.Count > 0)
            {
                return Results.Problem(
                    title: "Unknown permissions",
                    detail: $"Unknown permissions: {string.Join(", ", unknown)}",
                    statusCode: 400,
                    extensions: new Dictionary<string, object?> { ["unknownPermissions"] = unknown });
            }

            var change = await svc.SetAsync(role, requested, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(change);
        });

        permissionsGroup.MapPost("/{role}/rename", async (
            string role, RenameRoleRequest request, IRolePermissionService permissions,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var newRole = request.NewRole ?? string.Empty;
            RoleRenameOutcome outcome;
            try
            {
                outcome = await permissions.RenameRoleAsync(role, newRole, claimsMapper.GetName(httpContext.User), cancellationToken);
            }
            catch (ArgumentException ex)
            {
                return Results.Problem(title: "Invalid role name", detail: ex.Message, statusCode: 400);
            }

            return outcome switch
            {
                RoleRenameOutcome.Renamed => Results.Ok(new RoleRenameResponse(newRole, role)),
                RoleRenameOutcome.SourceNotFound => Results.Problem(
                    title: "Role not found", detail: $"No grants are stored for {role}.", statusCode: 404),
                _ => Results.Problem(
                    title: "Role already exists",
                    detail: $"{newRole} already has grants. A rename never merges two roles\u2019 grants.",
                    statusCode: 409)
            };
        });

        // Certificate requests — grouped with view permission on the group level
        var certificateRequests = v1.MapGroup("/certificate-requests")
            .RequireAuthorization(AppPermissions.CertificatesView)
            .RequireRateLimiting("api");

        certificateRequests.MapGet("/", async (CertificateRequestApiService service, int page = 1, int pageSize = 100,
            CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetAllAsync(page, pageSize, status, search, cancellationToken)));

        // Per-status counts for the list's filter chips. Separate from /summary, whose issued count
        // deliberately includes revoked certificates and so cannot label a single-status chip.
        certificateRequests.MapGet("/status-counts", async (CertificateRequestApiService service,
            string? search = null, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetStatusCountsAsync(search, cancellationToken)));

        certificateRequests.MapGet("/summary", async (CertificateRequestApiService service, CancellationToken cancellationToken) =>
            Results.Ok(await service.GetDashboardSummaryAsync(cancellationToken)));

        certificateRequests.MapGet("/issued", async (CertificateRequestApiService service, int page = 1, int pageSize = 100,
            IssuedCertificateFilter? filter = null, string? search = null, bool validOnly = false, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetIssuedAsync(page, pageSize, filter, search, validOnly, cancellationToken)));

        certificateRequests.MapGet("/issued/validity-counts", async (CertificateRequestApiService service,
            string? search = null, bool validOnly = false, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetIssuedValidityCountsAsync(search, validOnly, cancellationToken)));

        certificateRequests.MapGet("/rejected", async (CertificateRequestApiService service, int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetRejectedAsync(page, pageSize, cancellationToken)));

        certificateRequests.MapGet("/revoked", async (CertificateRequestApiService service, int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetRevokedAsync(page, pageSize, cancellationToken)));

        certificateRequests.MapGet("/expired", async (CertificateRequestApiService service, int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Results.Ok(await service.GetExpiredAsync(page, pageSize, cancellationToken)));

        certificateRequests.MapGet("/{id:guid}", async (Guid id, CertificateRequestApiService service, IIssuerRegistry issuers, HttpContext httpContext, CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();
            if (request.IssuerId is { } issuerId)
                request.IssuerName = (await issuers.GetAsync(issuerId, cancellationToken))?.Issuer.Name;
            ProgressHints.Apply(httpContext.Response, request.Status);
            return Results.Ok(request);
        });

        // History of one request. Webhook deliveries and diagnostics need settings.edit and key exports
        // are owner-or-admin; both are resolved here, because the permission policies succeed only
        // with the HttpContext as resource. What the caller may not see is listed as withheld.
        certificateRequests.MapGet("/{id:guid}/timeline", async (
            Guid id,
            CertificateRequestApiService service,
            Lifecycle.ICertificateTimelineService timeline,
            ICertificateAccessEvaluator accessEvaluator,
            IAuthorizationService authorization,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();

            var access = new Lifecycle.TimelineAccess(
                CanEditSettings: (await authorization.AuthorizeAsync(httpContext.User, httpContext, AppPermissions.SettingsEdit)).Succeeded,
                CanSeeKeyExports: accessEvaluator.CanAccessPrivateKey(httpContext.User, request),
                CallerSubject: claimsMapper.GetSubject(httpContext.User));
            var result = await timeline.GetAsync(new CertificateRequestId(id), access, cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Ok(result);
        });

        certificateRequests.MapPost("/", async (
            CreateCertificateRequestRequest request,
            IValidator<CreateCertificateRequestRequest> validator,
            CertificateRequestApiService service,
            ICertificateTemplateService templateService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            Policies.ICallerContextResolver callerResolver,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var template = await templateService.GetByTypeKeyAsync(request.Type, cancellationToken);
            if (template is null)
                return ApiProblem.BadRequest($"Unknown certificate type '{request.Type}'. Create a template for this type first.");

            var performedBy = claimsMapper.GetName(httpContext.User);
            var subject = claimsMapper.GetSubject(httpContext.User);
            var requester = Policies.RequesterRoles.From(claimsMapper.GetRoles(httpContext.User));
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            var certificateRequest = await service.CreateAsync(request, performedBy, subject, requester, caller, cancellationToken);
            return Results.Created($"/v1/certificate-requests/{certificateRequest.Id}", certificateRequest);
        }).RequireAuthorization(AppPermissions.CertificatesCreate);

        // Advisory only: writes nothing and gates nothing. A rejection is still 200 — the verdict is
        // the body's Allowed, so a client cannot confuse "would be refused" with "the call failed".
        certificateRequests.MapPost("/preview", async (
            CreateCertificateRequestRequest request,
            IValidator<CreateCertificateRequestRequest> validator,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            Policies.ICallerContextResolver callerResolver,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var requester = Policies.RequesterRoles.From(claimsMapper.GetRoles(httpContext.User));
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            return Results.Ok(await service.PreviewCreateAsync(request, requester, caller, cancellationToken));
        }).RequireAuthorization(AppPermissions.CertificatesCreate);

        certificateRequests.MapPut("/{id:guid}", async (
            Guid id,
            UpdateCertificateRequestRequest request,
            IValidator<UpdateCertificateRequestRequest> validator,
            CertificateRequestApiService service,
            ICertificateTemplateService templateService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            Policies.ICallerContextResolver callerResolver,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var template = await templateService.GetByTypeKeyAsync(request.Type, cancellationToken);
            if (template is null)
                return ApiProblem.BadRequest($"Unknown certificate type '{request.Type}'.");

            var performedBy = claimsMapper.GetName(httpContext.User);
            var requester = Policies.RequesterRoles.From(claimsMapper.GetRoles(httpContext.User));
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            var certificateRequest = await service.UpdateAsync(new CertificateRequestId(id), request, performedBy, requester, caller, cancellationToken);
            return certificateRequest is null ? ApiProblem.NotFound() : Results.Ok(certificateRequest);
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        certificateRequests.MapDelete("/{id:guid}", async (Guid id, CertificateRequestApiService service, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            try
            {
                var deleted = await service.DeleteAsync(new CertificateRequestId(id), performedBy, cancellationToken);
                return deleted ? Results.NoContent() : ApiProblem.NotFound();
            }
            catch (CertificateRequestDeletionConflictException ex)
            {
                return ApiProblem.Conflict(ex.Message);
            }
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        certificateRequests.MapPost("/{id:guid}/approve", async (Guid id, ApproveCertificateRequestRequest? body, CertificateRequestApiService service, ICertificateApprovalQueue approvalQueue, ICertificateRevocationQueue revocationQueue, IIssuerRegistry issuers, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, Policies.ICallerContextResolver callerResolver, CancellationToken cancellationToken) =>
        {
            var reqId = new CertificateRequestId(id);
            var performedBy = claimsMapper.GetName(httpContext.User);
            var existing = await service.GetByIdAsync(reqId, cancellationToken);
            if (existing is null) return ApiProblem.NotFound();
            if (existing.Status != CertificateRequestStatus.Pending)
                return ApiProblem.Conflict($"Cannot approve a request with status '{existing.Status}'.");
            if (existing.Type != WellKnownCertificateTypes.RootCa && await issuers.GetDefaultAsync(cancellationToken) is null)
                return ApiProblem.Conflict("The Root CA certificate has not been issued yet. Approve the Root CA request first.");
            var report = body?.PreviewedAllowed is { } shownAllowed
                ? new Policies.ApprovalPreviewReport(body.PreviewedPolicyVersionId, shownAllowed)
                : null;
            // Never null: a null caller skips the CA permission and independent-approver rules.
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            var result = await service.MarkAsApprovedAsync(reqId, performedBy, report, caller, cancellationToken);
            if (result is null) return ApiProblem.NotFound();

            approvalQueue.TrySignal();
            // If AutoRevokeOnRenewal queued a revocation, wake the worker for that too
            if (result.RenewedFromId.HasValue)
                revocationQueue.TrySignal();

            ProgressHints.Apply(httpContext.Response, result.Status);
            return Results.Ok(result);
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        // A GET that writes one audit entry on purpose: reading the verdict is the audited act.
        certificateRequests.MapGet("/{id:guid}/approval-preview", async (Guid id, CertificateRequestApiService service, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, Policies.ICallerContextResolver callerResolver, CancellationToken cancellationToken) =>
        {
            var existing = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (existing is null) return ApiProblem.NotFound();
            if (existing.Status != CertificateRequestStatus.Pending)
                return ApiProblem.Conflict($"Cannot preview approval of a request with status '{existing.Status}'.");
            // Never null: a null caller skips the CA permission and independent-approver rules.
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            return Results.Ok(await service.PreviewApprovalAsync(existing, claimsMapper.GetName(httpContext.User), caller, cancellationToken));
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        certificateRequests.MapPost("/{id:guid}/reject", async (Guid id, CertificateRequestApiService service, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var result = await service.MarkAsRejectedAsync(new CertificateRequestId(id), performedBy, cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Ok(result);
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        certificateRequests.MapPost("/{id:guid}/revoke", async (Guid id, RevokeRequest request, CertificateRequestApiService service, ICertificateRevocationQueue revocationQueue, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var result = await service.MarkAsPendingRevocationAsync(new CertificateRequestId(id), request.Reason, performedBy, cancellationToken);
            if (result is null) return ApiProblem.NotFound();
            revocationQueue.TrySignal();
            ProgressHints.Apply(httpContext.Response, result.Status);
            return Results.Accepted($"/v1/certificate-requests/{id}", result);
        }).RequireAuthorization(AppPermissions.CertificatesManage);

        certificateRequests.MapPost("/{id:guid}/renew", async (Guid id, CertificateRequestApiService service, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, Policies.ICallerContextResolver callerResolver, CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var caller = await CallerOf(httpContext, claimsMapper, callerResolver, cancellationToken);
            var result = await service.RenewAsync(new CertificateRequestId(id), performedBy, caller, cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Created($"/v1/certificate-requests/{result.Id}", result);
        }).RequireAuthorization(AppPermissions.CertificatesCreate);

        // ── Certificate material downloads ────────────────────────────────────────
        // The private key never appears in list or detail responses ([JsonIgnore] on the entity).
        // These are the only routes that can return it, and each one runs the ownership check.

        // Metadata is a typed set of facts about the certificate (owner team, contact, purpose, target,
        // ticket, compatibility). Read with certificates.view; written by the owner or certificates.manage,
        // resolved here because the permission policies succeed only with the HttpContext as resource.
        // Existence and access are decided before the body is validated, so a stranger learns nothing.
        certificateRequests.MapPut("/{id:guid}/metadata", async (
            Guid id,
            CertificateMetadata body,
            IValidator<CertificateMetadata> validator,
            CertificateRequestApiService service,
            ICertificateAccessEvaluator accessEvaluator,
            IAuthorizationService authorization,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();

            var canManage = (await authorization.AuthorizeAsync(httpContext.User, httpContext, AppPermissions.CertificatesManage)).Succeeded;
            if (!accessEvaluator.CanEditMetadata(httpContext.User, request, canManage))
                return Results.Forbid();

            var validation = await validator.ValidateAsync(body, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var updated = await service.UpdateMetadataAsync(request.Id, body, claimsMapper.GetName(httpContext.User), cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated.Metadata);
        }).RequireAuthorization(AppPermissions.CertificatesView);

        certificateRequests.MapGet("/{id:guid}/private-key", async (
            Guid id,
            [FromQuery] bool pqc,
            CertificateRequestApiService service,
            ICertificateAccessEvaluator accessEvaluator,
            IAuditLogService auditLog,
            IWebhookService webhookService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();

            if (!accessEvaluator.CanAccessPrivateKey(httpContext.User, request))
                return Results.Forbid();

            if (request.Status is not (CertificateRequestStatus.Issued or CertificateRequestStatus.Revoked))
                return ApiProblem.NotFound();

            var keyPem = pqc ? request.PqcPrivateKeyPem : request.PrivateKeyPem;
            // ACME-issued requests store an empty key: the client generated it and the CA never saw it.
            if (string.IsNullOrWhiteSpace(keyPem))
                return ApiProblem.NotFound();

            var performedBy = claimsMapper.GetName(httpContext.User);
            await auditLog.LogAsync("PrivateKeyDownloaded", performedBy, id, request.CommonName,
                KeyAccessAudit.PrivateKeyDetail(request.KeyAlgorithm, pqc), cancellationToken);

            // KeyAccess deliberately carries no common name and no request id — WebhookService
            // suppresses both — so the thumbprint is what identifies the key that left.
            var downloadedCertPem = pqc ? request.PqcCertificatePem : request.CertificatePem;
            await webhookService.EnqueueEventAsync(new WebhookEvent(
                WellKnownWebhookEvents.PrivateKeyDownloaded,
                PerformedBy: performedBy,
                Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["publicKeyThumbprint"] = PublicKeyThumbprint.FromCertificatePem(downloadedCertPem)
                }), cancellationToken);

            return Results.Bytes(
                System.Text.Encoding.ASCII.GetBytes(keyPem),
                "application/x-pem-file",
                $"{SafeFileName(request.CommonName)}.key");
        });

        certificateRequests.MapPost("/{id:guid}/pfx", async (
            Guid id,
            ExportPfxRequest body,
            CertificateRequestApiService service,
            ICertificateAccessEvaluator accessEvaluator,
            IIssuerRegistry issuers,
            IAuditLogService auditLog,
            IWebhookService webhookService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();

            if (!accessEvaluator.CanAccessPrivateKey(httpContext.User, request))
                return Results.Forbid();

            if (request.Status is not (CertificateRequestStatus.Issued or CertificateRequestStatus.Revoked))
                return ApiProblem.NotFound();

            var certPem = body.Pqc ? request.PqcCertificatePem : request.CertificatePem;
            var keyPem = body.Pqc ? request.PqcPrivateKeyPem : request.PrivateKeyPem;
            if (string.IsNullOrWhiteSpace(certPem) || string.IsNullOrWhiteSpace(keyPem))
                return ApiProblem.NotFound();

            // The issuing CA and every CA above it, root included, as today's single-root chain includes the root.
            IReadOnlyList<string> chain = [];
            if (body.IncludeChain && await issuers.ForRequestAsync(request, cancellationToken) is { } issuer)
                chain = await issuers.ChainForAsync(issuer.Issuer.Id, cancellationToken);

            byte[] pfxBytes;
            try
            {
                // Built by BouncyCastle for every algorithm: the BCL cannot put a composite key in a PFX.
                pfxBytes = QertumKeyCodec.ExportPkcs12(certPem, keyPem, chain, body.Password, request.CommonName);
            }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or Org.BouncyCastle.Crypto.CryptoException
                                           or Org.BouncyCastle.Security.SecurityUtilityException)
            {
                return Results.Problem($"Cannot export this certificate as PKCS#12: {ex.Message}", statusCode: 400);
            }

            var performedBy = claimsMapper.GetName(httpContext.User);
            await auditLog.LogAsync("PfxExported", performedBy, id, request.CommonName,
                KeyAccessAudit.PfxDetail(request.KeyAlgorithm, body.Pqc, body.IncludeChain), cancellationToken);

            await webhookService.EnqueueEventAsync(new WebhookEvent(
                WellKnownWebhookEvents.PfxExported,
                PerformedBy: performedBy,
                Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["publicKeyThumbprint"] = PublicKeyThumbprint.FromCertificatePem(certPem)
                }), cancellationToken);

            return Results.Bytes(pfxBytes, "application/x-pkcs12", $"{SafeFileName(request.CommonName)}.pfx");
        });

        // Certificates are public material — no ownership check, only certificates.view.
        certificateRequests.MapGet("/{id:guid}/certificate", async (
            Guid id,
            [FromQuery] string? format,
            [FromQuery] bool pqc,
            CertificateRequestApiService service,
            CancellationToken cancellationToken) =>
        {
            var request = await service.GetByIdAsync(new CertificateRequestId(id), cancellationToken);
            if (request is null) return ApiProblem.NotFound();

            var certPem = pqc ? request.PqcCertificatePem : request.CertificatePem;
            if (string.IsNullOrWhiteSpace(certPem))
                return ApiProblem.NotFound();

            var name = SafeFileName(request.CommonName);
            return (format ?? "pem").ToLowerInvariant() switch
            {
                "cer" => Results.Bytes(
                    X509Certificate2.CreateFromPem(certPem).Export(X509ContentType.Cert),
                    "application/pkix-cert", $"{name}.cer"),
                "p7b" => Results.Bytes(
                    new X509Certificate2Collection(X509Certificate2.CreateFromPem(certPem))
                        .Export(X509ContentType.Pkcs7)!,
                    "application/x-pkcs7-certificates", $"{name}.p7b"),
                "crt" => Results.Bytes(
                    System.Text.Encoding.ASCII.GetBytes(certPem),
                    "application/x-x509-ca-cert", $"{name}.crt"),
                _ => Results.Bytes(
                    System.Text.Encoding.ASCII.GetBytes(certPem),
                    "application/x-pem-file", $"{name}.pem")
            };
        });

        // Public endpoint — no auth required, PKI clients must be able to fetch the CRL.
        // Served at both /crl (legacy PKI infrastructure compatibility) and /v1/crl.
        // Uses IDistributedCache so the cache is shared across API instances in multi-node deployments.
        MapCrlEndpoint(endpoints, "/crl");
        MapCrlEndpoint(v1, "/crl");

        // Delta CRL (RFC 5280 §5.2.4) — only ever answers relative to the base the full-CRL endpoint
        // most recently published; see MapDeltaCrlEndpoint. Same public/no-auth shape as /crl.
        MapDeltaCrlEndpoint(endpoints, "/crl/delta");
        MapDeltaCrlEndpoint(v1, "/crl/delta");

        // Admin-only: force a fresh full CRL and delta base on demand, rather than waiting for the
        // next /crl fetch to do it as a side effect. Same auth shape as /v1/settings.
        v1.MapPost("/crl/reset-base", async (
            [FromQuery] Guid? issuerId,
            CrlPublisher crlPublisher, IIssuerRegistry issuers,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper, IAuditLogService auditLog,
            CancellationToken cancellationToken) =>
        {
            var issuer = issuerId is { } id
                ? await issuers.GetAsync(new IssuerId(id), cancellationToken)
                : await issuers.ForUnscopedCrlAsync(cancellationToken);
            if (issuer is null)
                return issuerId is null
                    ? Results.Problem("CA certificate not configured.", statusCode: 503)
                    : ApiProblem.NotFound();
            if (!issuer.CanSignRevocation)
                return ApiProblem.Conflict("This issuer cannot sign a CRL.");

            var published = await crlPublisher.PublishFullCrlAsync(issuer, cancellationToken);

            var performedBy = claimsMapper.GetName(httpContext.User);
            await auditLog.LogAsync("CrlBaseReset", performedBy,
                detail: issuer.Issuer.LegacyFiles
                    ? $"crlNumber={published.CrlNumber}"
                    : $"crlNumber={published.CrlNumber}, issuer={issuer.Issuer.Name}",
                cancellationToken: cancellationToken);

            return Results.Ok(new CrlBaseResetResponse(published.CrlNumber, published.ThisUpdateUtc));
        }).WithTags("Crl").RequireAuthorization(AppPermissions.SettingsEdit);


        MapOcspEndpoints(endpoints, "/ocsp");
        MapOcspEndpoints(v1, "/ocsp");

        var settingsGroup = v1.MapGroup("/settings").WithTags("Settings")
            .RequireAuthorization(AppPermissions.SettingsEdit);

        settingsGroup.MapGet("/", async (CertificateRequestApiService service, CancellationToken cancellationToken) =>
        {
            var result = await service.GetSettingsAsync(cancellationToken);
            return Results.Ok(result);
        });

        // Loosening enforcement must not be reachable through settings.edit: a holder could otherwise
        // switch off the rule that stops it issuing classical keys. Admin only, like permission grants.
        settingsGroup.MapPut("/pqc-stage", async (
            SetPqcStageRequest request,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.Stage is not { } stage || !Enum.IsDefined(stage))
                return ApiProblem.BadRequest($"stage must be one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");

            var result = await service.SetPqcStageAsync(stage, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(result);
        }).RequireAuthorization("admin-role");

        // Loosening the strength comparison lets a CA vouch for a key stronger than its own, so like the PQC stage it
        // is admin-only and never a grantable permission.
        settingsGroup.MapPut("/issuer-strength", async (
            SetIssuerStrengthRequest request,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.Mode is not { } mode || !Enum.IsDefined(mode))
                return ApiProblem.BadRequest($"mode must be one of {string.Join(", ", Enum.GetNames<IssuerStrengthMode>())}.");

            var result = await service.SetIssuerStrengthAsync(mode, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(result);
        }).RequireAuthorization("admin-role");

        // Choosing Retire leaves the rest of a hierarchy issuing under a revoked ancestor, so like the PQC stage
        // it is admin-only and never a grantable permission.
        settingsGroup.MapPut("/revoked-issuer", async (
            SetRevokedIssuerModeRequest request,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.Mode is not { } mode || !Enum.IsDefined(mode))
                return ApiProblem.BadRequest($"mode must be one of {string.Join(", ", Enum.GetNames<RevokedIssuerMode>())}.");

            var result = await service.SetRevokedIssuerModeAsync(mode, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(result);
        }).RequireAuthorization("admin-role");

        // Waiving independent approval lets one person issue a CA end to end, so like the PQC stage it
        // is admin-only and never a grantable permission.
        settingsGroup.MapPut("/ca-approval", async (
            SetCaApprovalRequest request,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.RequireIndependentApproval is not { } require)
                return ApiProblem.BadRequest("requireIndependentApproval must be true or false.");

            var result = await service.SetCaApprovalRuleAsync(require, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(result);
        }).RequireAuthorization("admin-role");

        // Switching the check off removes a protection, so like the CA approval rule it is admin-only and on the
        // step-up table. It does not need an approval itself: a one-administrator deployment must be able to turn it off.
        settingsGroup.MapPut("/two-person-approval", async (
            SetTwoPersonApprovalRequest request,
            CertificateRequestApiService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.Enabled is not { } enabled)
                return ApiProblem.BadRequest("enabled must be true or false.");

            var result = await service.SetTwoPersonApprovalAsync(enabled, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Ok(result);
        }).RequireAuthorization("admin-role");

        settingsGroup.MapPut("/", async (
            CaSettings settings,
            IValidator<CaSettings> validator,
            CertificateRequestApiService service,
            Policies.IIssuancePolicyManagementService policyManagement,
            IAuthorizationService authorization,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(settings, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            // The protocol keys decide which policy governs ACME and EST issuance, so moving one is
            // a change to what is enforced — the same authority as publishing a version, not the
            // settings.edit this group otherwise requires.
            var current = await service.GetSettingsAsync(cancellationToken);
            if (current is not null &&
                (!string.Equals(current.AcmeTemplateTypeKey, settings.AcmeTemplateTypeKey, StringComparison.Ordinal) ||
                 !string.Equals(current.EstTemplateTypeKey, settings.EstTemplateTypeKey, StringComparison.Ordinal)) &&
                !(await authorization.AuthorizeAsync(httpContext.User, httpContext, AppPermissions.PoliciesPublish)).Succeeded)
            {
                return Results.Forbid();
            }

            var settingsError = await policyManagement.ValidateSettingsAsync(settings, cancellationToken);
            if (settingsError is not null)
                return ApiProblem.BadRequest(settingsError);

            var performedBy = claimsMapper.GetName(httpContext.User);
            var result = await service.SetupOrUpdateSettingsAsync(settings, performedBy, cancellationToken);
            return Results.Ok(result);
        });

        var secretStorageGroup = v1.MapGroup("/secret-storage").WithTags("SecretStorage")
            .RequireAuthorization(AppPermissions.SettingsEdit);
        // The data directory is server configuration (a singleton), resolved once here rather than as a handler
        // parameter, so nothing about the request can ever be mistaken for, or bound into, a file-system path.
        var options = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<SecretStorageOptions>(((IEndpointRouteBuilder)v1).ServiceProvider);

        secretStorageGroup.MapGet("/status", () =>
        {
            var provider = Qertum.ServiceDefaults.Secrets.SecretStorageConfig.Read(options.DataDirectory);
            var tpmAvailable = Qertum.ServiceDefaults.Secrets.TpmSecretProtector.IsAvailable();

            return Results.Ok(new SecretStorageStatusResponse(provider.ToString(), tpmAvailable));
        });

        secretStorageGroup.MapPost("/migrate", async (
            MigrateSecretStorageRequest request,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            IAuditLogService auditLog,
            CancellationToken cancellationToken) =>
        {
            if (!Enum.TryParse<Qertum.ServiceDefaults.Secrets.SecretStorageProvider>(request.TargetProvider, out var targetProvider))
                return ApiProblem.BadRequest($"Unknown provider '{request.TargetProvider}'.");

            var currentProviderName = Qertum.ServiceDefaults.Secrets.SecretStorageConfig.Read(options.DataDirectory).ToString();

            try
            {
                MigrateSecretStorage(options.DataDirectory, targetProvider);
            }
            catch (Exception ex)
            {
                return Results.Problem($"Migration failed and was rolled back: {ex.Message}", statusCode: 500);
            }

            var performedBy = claimsMapper.GetName(httpContext.User);
            await auditLog.LogAsync("SecretStorageMigrated", performedBy,
                detail: $"{currentProviderName} -> {targetProvider}", cancellationToken: cancellationToken);

            return Results.Accepted(value: new { RestartRequired = true });
        });

        // CA lifecycle — status is readable by any authenticated user; generate/import require settings.edit
        var caGroup = v1.MapGroup("/ca").RequireAuthorization();

        caGroup.MapGet("/status", async (IIssuerRegistry issuers, CertificateRequestApiService requestService, CertificateRequestDbContext db, CancellationToken cancellationToken) =>
        {
            var handle = await issuers.GetDefaultAsync(cancellationToken);
            var status = handle?.Generator?.GetCaStatus() ?? new CaStatusResponse { IsInitialized = false };
            if (handle?.RecordedIssuerId is { } defaultId)
            {
                status.DefaultIssuerId = defaultId;
                status.DefaultIssuerName = handle.Issuer.Name;
            }
            if (!status.IsInitialized)
            {
                status.PendingRootCaRequestId = await requestService.GetPendingRootCaRequestIdAsync(cancellationToken);
                status.PendingIntermediateIssuerId = (await issuers.GetAllAsync(cancellationToken))
                    .FirstOrDefault(i => i.Status == IssuerStatus.PendingCertificate)?.Id;
                status.IssuerRevoked = await IssuerQueries.AnyRevokedAsync(db, cancellationToken);
                if (status.IssuerRevoked) status.RevokedIssuerKind = await IssuerQueries.LatestRevokedKindAsync(db, cancellationToken);
            }
            return Results.Ok(status);
        });

        caGroup.MapGet("/certificate", async ([FromQuery] string? format, IIssuerRegistry issuers, CancellationToken cancellationToken) =>
        {
            // The default issuer's root: the trust anchor clients install.
            var handle = await issuers.GetDefaultAsync(cancellationToken);
            IReadOnlyList<string> chain = handle is null ? [] : await issuers.ChainForAsync(handle.Issuer.Id, cancellationToken);
            if (chain.Count == 0) return Results.Problem("CA is not initialized.", statusCode: 503);
            var pem = chain[^1];

            return (format ?? "pem").ToLowerInvariant() switch
            {
                "der" => Results.Bytes(
                    X509Certificate2.CreateFromPem(pem).Export(X509ContentType.Cert),
                    "application/x-x509-ca-cert", "ca.cer"),
                "p7b" => Results.Bytes(
                    new X509Certificate2Collection(X509Certificate2.CreateFromPem(pem))
                        .Export(X509ContentType.Pkcs7)!,
                    "application/x-pkcs7-certificates", "ca.p7b"),
                _ => Results.Bytes(
                    System.Text.Encoding.ASCII.GetBytes(pem),
                    "application/x-pem-file", "ca.pem")
            };
        });

        caGroup.MapPost("/generate", async (
            GenerateCaRequest request,
            [FromQuery] bool? force,
            IValidator<GenerateCaRequest> validator,
            IIssuerRegistry issuers,
            IAuthorizationService authorization,
            CertificateRequestDbContext db,
            CertificateRequestApiService service,
            IAuditLogService auditLog,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var current = await issuers.GetDefaultAsync(cancellationToken);
            if (current is not null)
            {
                if (force != true)
                    return ApiProblem.Conflict("A CA certificate already exists on this server.");
                var refusal = await ForceGuardAsync(authorization, httpContext, current, request.Confirm);
                if (refusal is not null) return refusal;
            }

            var existingPendingId = await service.GetPendingRootCaRequestIdAsync(cancellationToken);
            if (existingPendingId.HasValue)
                return ApiProblem.Conflict("A Root CA generation request is already pending approval.");

            var performedBy = claimsMapper.GetName(httpContext.User);

            // Onboarding chooses the stage together with the root key, so a classical root can be a
            // deliberate choice. Changing the stage stays admin-only here too.
            if (request.PqcStage is { } requestedStage)
            {
                if (!Enum.IsDefined(requestedStage))
                    return ApiProblem.BadRequest($"pqcStage must be one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");
                var currentStage = (await service.GetSettingsAsync(cancellationToken)).PqcStage;
                if (requestedStage != currentStage)
                {
                    if (!(await authorization.AuthorizeAsync(httpContext.User, "admin-role")).Succeeded)
                        return Results.Forbid();
                    await service.SetPqcStageAsync(requestedStage, performedBy, cancellationToken);
                }
            }

            var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
            var props = System.Text.Json.JsonSerializer.Serialize(new RootCaProperties
            {
                OrganizationName = request.OrganizationName,
                OrganizationalUnit = request.OrganizationalUnit,
                Country = request.Country,
                State = request.State,
                Locality = request.Locality,
                ValidityDays = request.ValidityDays > 0 ? request.ValidityDays : 3650,
                ReplaceIssuerId = current?.RecordedIssuerId,
                AfterRevokedIssuer = current is null && await IssuerQueries.AnyRevokedAsync(db, cancellationToken)
            });

            var certRequest = await service.CreateRootCaRequestAsync(
                request.CommonName, algorithm, props, performedBy,
                claimsMapper.GetSubject(httpContext.User), cancellationToken);

            var replaces = current is null ? "" : $" Replaces '{current.Issuer.Name}' when signed.";
            await auditLog.LogAsync("CaGenerationRequested", performedBy, resourceName: request.CommonName,
                detail: $"Root CA generation requested. Algorithm: {algorithm.ToCanonicalString()}, validity: {request.ValidityDays} days.{replaces}",
                cancellationToken: cancellationToken);

            return Results.Created($"/v1/certificate-requests/{certRequest.Id}", certRequest);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        caGroup.MapPost("/import", async (
            ImportCaRequest request,
            [FromQuery] bool? force,
            IValidator<ImportCaRequest> validator,
            ICertificateGenerator certGen,
            IIssuerRegistry issuers,
            IssuerStorage storage,
            IssuerLifecycleService lifecycle,
            Microsoft.AspNetCore.DataProtection.IDataProtectionProvider dataProtection,
            ILoggerFactory loggerFactory,
            IAuthorizationService authorization,
            CertificateRequestDbContext db,
            CertificateRequestApiService service,
            IAuditLogService auditLog,
            TimeProvider clock,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var existingSettings = await service.GetSettingsAsync(cancellationToken);
            var policyError = ValidateImportAlgorithmPolicy(existingSettings, request.CertificatePem);
            if (policyError is not null)
                return policyError;

            var current = await issuers.GetDefaultAsync(cancellationToken);
            var performedBy = claimsMapper.GetName(httpContext.User);
            // No default because a revoked certificate took every issuer out of service: the legacy files still
            // hold the revoked key, so the new root goes into its own directory like a replacement does.
            var afterRevoked = current is null && await IssuerQueries.AnyRevokedAsync(db, cancellationToken);
            if (current is not null || afterRevoked)
            {
                if (current is not null)
                {
                    if (force != true)
                        return ApiProblem.Conflict("A CA certificate already exists on this server.");
                    var refusal = await ForceGuardAsync(authorization, httpContext, current, request.Confirm);
                    if (refusal is not null) return refusal;
                }

                // The replacement is imported into its own directory first; the old CA is only
                // destroyed once the import (parsing, cA=true, key match) has succeeded.
                var replacement = new Issuer
                {
                    Name = "pending", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
                    CreatedAtUtc = clock.GetUtcNow().UtcDateTime
                };
                var generator = new CertificateGenerator(dataProtection, storage.OptionsFor(replacement),
                    loggerFactory.CreateLogger<CertificateGenerator>(), timeProvider: clock);
                try
                {
                    generator.ImportCa(request);
                }
                catch (ArgumentException ex)
                {
                    storage.DeleteFiles(replacement);
                    return ApiProblem.BadRequest(ex.Message);
                }

                var facts = IssuerCertificateFacts.Read(request.CertificatePem);
                facts.ApplyTo(replacement);
                replacement.Name = await IssuerNames.UniqueAsync(db, IssuerBootstrap.NameFrom(facts.SubjectDn), cancellationToken);
                replacement.Kind = facts.IsSelfSigned ? IssuerKind.Root : IssuerKind.Intermediate;
                replacement.CertificatePem = generator.GetCaCertificatePem();
                if (current is not null)
                    await lifecycle.ReplaceDefaultAsync(current.Issuer, replacement, performedBy, cancellationToken);
                else
                    await lifecycle.RegisterDefaultAsync(replacement, performedBy, cancellationToken);
            }
            else
            {
                try
                {
                    certGen.ImportCa(request);
                }
                catch (InvalidOperationException ex)
                {
                    return ApiProblem.Conflict(ex.Message);
                }
                catch (ArgumentException ex)
                {
                    return ApiProblem.BadRequest(ex.Message);
                }
                await issuers.InvalidateAsync(cancellationToken);
            }

            // Persist DN fields extracted from the imported cert so the Settings page reflects them
            var status = (await issuers.GetDefaultAsync(cancellationToken))?.Generator?.GetCaStatus() ?? certGen.GetCaStatus();
            existingSettings.OrganizationName = status.OrganizationName;
            existingSettings.OrganizationalUnit = status.OrganizationalUnit;
            existingSettings.Country = status.Country;
            existingSettings.State = status.State;
            existingSettings.Locality = status.Locality;
            await service.SetupOrUpdateSettingsAsync(existingSettings, performedBy, cancellationToken);

            await auditLog.LogAsync("CaImported", performedBy, resourceName: status.SubjectDn,
                detail: current is null
                    ? "CA certificate imported from PEM."
                    : $"CA certificate imported from PEM, replacing '{current.Issuer.Name}'.",
                cancellationToken: cancellationToken);

            return Results.Ok(status);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        // Certificate templates — list is view-accessible; mutations require settings.edit
        var templatesGroup = v1.MapGroup("/certificate-templates");

        templatesGroup.MapGet("/", async (ICertificateTemplateService templateService, CancellationToken cancellationToken) =>
            Results.Ok(await templateService.GetAllAsync(cancellationToken)))
            .RequireAuthorization(AppPermissions.CertificatesView);

        templatesGroup.MapGet("/{id:guid}", async (Guid id, ICertificateTemplateService templateService, CancellationToken cancellationToken) =>
        {
            var template = await templateService.GetByIdAsync(new CertificateTemplateId(id), cancellationToken);
            return template is null ? ApiProblem.NotFound() : Results.Ok(template);
        }).RequireAuthorization(AppPermissions.CertificatesView);

        templatesGroup.MapPost("/", async (
            SaveCertificateTemplateRequest request,
            IValidator<SaveCertificateTemplateRequest> validator,
            ICertificateTemplateService templateService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var existing = await templateService.GetByTypeKeyAsync(request.TypeKey, cancellationToken);
            if (existing is not null)
                return ApiProblem.Conflict($"A template with TypeKey '{request.TypeKey}' already exists.");

            var performedBy = claimsMapper.GetName(httpContext.User);
            var template = await templateService.CreateAsync(new CertificateTemplate
            {
                Name = request.Name,
                TypeKey = request.TypeKey,
                Description = request.Description,
                KeyUsagesJson = request.KeyUsagesJson,
                ExtendedKeyUsagesJson = request.ExtendedKeyUsagesJson,
                SanTypesJson = request.SanTypesJson,
                CustomExtensionsJson = request.CustomExtensionsJson,
                ValidityDays = request.ValidityDays
            }, performedBy, cancellationToken);
            return Results.Created($"/v1/certificate-templates/{template.Id}", template);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        templatesGroup.MapPut("/{id:guid}", async (
            Guid id,
            SaveCertificateTemplateRequest request,
            IValidator<SaveCertificateTemplateRequest> validator,
            ICertificateTemplateService templateService,
            Policies.IIssuancePolicyManagementService policyManagement,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var current = await templateService.GetByIdAsync(new CertificateTemplateId(id), cancellationToken);
            if (current is null)
                return ApiProblem.NotFound();

            // The save never changes the policy link, but a new default validity must still fit
            // under the linked policy's maximum (throws IssuancePolicyInvariantException -> 422).
            var linkError = await policyManagement.ValidateTemplateLinkAsync(
                current.IssuancePolicyId, current.TypeKey, request.ValidityDays, cancellationToken);
            if (linkError is not null)
                return ApiProblem.BadRequest(linkError);

            var performedBy = claimsMapper.GetName(httpContext.User);
            var result = await templateService.UpdateAsync(new CertificateTemplateId(id), new CertificateTemplate
            {
                Name = request.Name,
                TypeKey = request.TypeKey,
                Description = request.Description,
                KeyUsagesJson = request.KeyUsagesJson,
                ExtendedKeyUsagesJson = request.ExtendedKeyUsagesJson,
                SanTypesJson = request.SanTypesJson,
                CustomExtensionsJson = request.CustomExtensionsJson,
                ValidityDays = request.ValidityDays
            }, performedBy, cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Ok(result);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        // Changing which policy governs a template changes what is enforced, so it needs
        // policies.publish — the same permission as publishing a policy version.
        templatesGroup.MapPut("/{id:guid}/issuance-policy", async (
            Guid id,
            SetTemplateIssuancePolicyRequest request,
            ICertificateTemplateService templateService,
            Policies.IIssuancePolicyManagementService policyManagement,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var template = await templateService.GetByIdAsync(new CertificateTemplateId(id), cancellationToken);
            if (template is null)
                return ApiProblem.NotFound();

            var linkError = await policyManagement.ValidateTemplateLinkAsync(
                request.IssuancePolicyId, template.TypeKey, template.ValidityDays, cancellationToken);
            if (linkError is not null)
                return ApiProblem.BadRequest(linkError);

            var updated = await templateService.SetIssuancePolicyAsync(new CertificateTemplateId(id),
                request.IssuancePolicyId, claimsMapper.GetName(httpContext.User), cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        }).RequireAuthorization(AppPermissions.PoliciesPublish);

        // Only issuers that can sign right now may be pinned; one retired later makes the
        // template's requests refuse with 409 (IssuerNotActiveException) rather than fall back.
        templatesGroup.MapPut("/{id:guid}/pqc-stage", async (
            Guid id,
            SetTemplatePqcStageRequest request,
            ICertificateTemplateService templateService,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.Stage is { } stage && !Enum.IsDefined(stage))
                return ApiProblem.BadRequest($"stage must be null or one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");

            var updated = await templateService.SetPqcStageAsync(new CertificateTemplateId(id), request.Stage,
                claimsMapper.GetName(httpContext.User), cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        }).RequireAuthorization("admin-role");

        templatesGroup.MapPut("/{id:guid}/issuer", async (
            Guid id,
            SetTemplateIssuerRequest request,
            ICertificateTemplateService templateService,
            Issuers.IIssuerRegistry issuers,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            if (request.IssuerId is { } issuerId)
            {
                var handle = await issuers.GetAsync(issuerId, cancellationToken);
                if (handle is null) return ApiProblem.NotFound($"Issuer {issuerId} does not exist.");
                if (!handle.CanIssue)
                    return Results.Problem(
                        $"Issuer '{handle.Issuer.Name}' cannot issue (status {handle.Issuer.Status}, {handle.Issuer.KeyCustody}).",
                        statusCode: StatusCodes.Status422UnprocessableEntity, title: "Issuer Cannot Issue");
            }

            var updated = await templateService.SetIssuerAsync(new CertificateTemplateId(id), request.IssuerId,
                claimsMapper.GetName(httpContext.User), cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        templatesGroup.MapDelete("/{id:guid}", async (Guid id, ICertificateTemplateService templateService, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            try
            {
                var deleted = await templateService.DeleteAsync(new CertificateTemplateId(id), performedBy, cancellationToken);
                return deleted ? Results.NoContent() : ApiProblem.NotFound();
            }
            catch (InvalidOperationException ex)
            {
                return ApiProblem.BadRequest(ex.Message);
            }
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        v1.MapIssuancePolicyApi();
        v1.MapBulkOperationApi();
        v1.MapApprovalApi();
        v1.MapNoticeApi();
        v1.MapCertificateNoteApi();
        v1.MapIssuerApi();
        v1.MapPqcApi();
        v1.MapPqcReportApi();

        // Webhooks — settings.edit only
        var webhooksGroup = v1.MapGroup("/webhooks").RequireAuthorization(AppPermissions.SettingsEdit);

        webhooksGroup.MapGet("/", async (IWebhookService webhookService, CancellationToken cancellationToken) =>
            Results.Ok(await webhookService.GetAllAsync(cancellationToken)));

        webhooksGroup.MapGet("/{id:guid}", async (Guid id, IWebhookService webhookService, CancellationToken cancellationToken) =>
        {
            var webhook = await webhookService.GetByIdAsync(new WebhookId(id), cancellationToken);
            return webhook is null ? ApiProblem.NotFound() : Results.Ok(webhook);
        });

        webhooksGroup.MapPost("/", async (
            SaveWebhookRequest request,
            IValidator<SaveWebhookRequest> validator,
            IWebhookService webhookService,
            IWebhookDestinationPolicyService destinations,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var destinationPolicy = await destinations.GetEffectiveAsync(cancellationToken);
            if (!destinations.CanSaveUrl(destinationPolicy, request.Url, out var destinationError))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["Url"] = [destinationError!] });

            var performedBy = claimsMapper.GetName(httpContext.User);
            var webhook = new Webhook
            {
                Name = request.Name,
                Url = request.Url,
                Family = request.Family,
                Secret = string.IsNullOrEmpty(request.Secret) ? null : request.Secret,
                EventsJson = request.EventsJson,
                IsEnabled = request.IsEnabled
            };
            var created = await webhookService.CreateAsync(webhook, performedBy, cancellationToken);
            return Results.Created($"/v1/webhooks/{created.Id}", created);
        });

        webhooksGroup.MapPut("/{id:guid}", async (
            Guid id,
            SaveWebhookRequest request,
            IValidator<SaveWebhookRequest> validator,
            IWebhookService webhookService,
            IWebhookDestinationPolicyService destinations,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var destinationPolicy = await destinations.GetEffectiveAsync(cancellationToken);
            if (!destinations.CanSaveUrl(destinationPolicy, request.Url, out var destinationError))
                return Results.ValidationProblem(new Dictionary<string, string[]> { ["Url"] = [destinationError!] });

            var performedBy = claimsMapper.GetName(httpContext.User);
            var updated = await webhookService.UpdateAsync(new WebhookId(id), new Webhook
            {
                Name = request.Name,
                Url = request.Url,
                Family = request.Family,
                Secret = request.Secret,   // null = keep, "" = clear (handled in service)
                EventsJson = request.EventsJson,
                IsEnabled = request.IsEnabled
            }, performedBy, cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        });

        webhooksGroup.MapDelete("/{id:guid}", async (Guid id, IWebhookService webhookService, HttpContext httpContext, IIdentityClaimsMapper claimsMapper, CancellationToken cancellationToken) =>
        {
            var deleted = await webhookService.DeleteAsync(new WebhookId(id), claimsMapper.GetName(httpContext.User), cancellationToken);
            return deleted ? Results.NoContent() : ApiProblem.NotFound();
        });

        v1.MapWebhookDestinationApi();

        // ACME external account credentials — the gate on who may register an ACME account.
        // ACME orders for operators: which names are stuck and why. settings.edit, because the
        // history exposes internal addresses, resolver answers and the challenge allowlist.
        var acmeOrdersGroup = v1.MapGroup("/acme/orders").RequireAuthorization(AppPermissions.SettingsEdit);

        acmeOrdersGroup.MapGet("/", async (Acme.IAcmeOrderQueryService orders, string? search = null,
            bool failing = false, int page = 1, int pageSize = 50, CancellationToken cancellationToken = default) =>
            Results.Ok(await orders.ListAsync(search, failing, page, pageSize, cancellationToken)));

        acmeOrdersGroup.MapGet("/{id:guid}", async (Guid id, Acme.IAcmeOrderQueryService orders,
            CancellationToken cancellationToken) =>
            await orders.GetAsync(id, cancellationToken) is { } detail
                ? Results.Ok(detail)
                : ApiProblem.NotFound($"No ACME order with id {id}."));

        var eabGroup = v1.MapGroup("/acme/external-account-keys").RequireAuthorization(AppPermissions.SettingsEdit);

        eabGroup.MapGet("/", async (Acme.IAcmeExternalAccountKeyService svc, CancellationToken cancellationToken) =>
            Results.Ok(await svc.GetAllAsync(cancellationToken)));

        eabGroup.MapPost("/", async (
            CreateAcmeExternalAccountKeyRequest request,
            Acme.IAcmeExternalAccountKeyService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var created = await svc.CreateAsync(request.Description, performedBy, cancellationToken);
            // The MAC key is in this response and nowhere else — nothing reads it back afterwards.
            return Results.Created($"/v1/acme/external-account-keys/{created.Credential.Id}", created);
        });

        eabGroup.MapPut("/{id:guid}", async (
            Guid id,
            UpdateAcmeExternalAccountKeyRequest request,
            Acme.IAcmeExternalAccountKeyService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var updated = await svc.SetEnabledAsync(id, request.IsEnabled, performedBy, cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        });

        eabGroup.MapDelete("/{id:guid}", async (
            Guid id,
            Acme.IAcmeExternalAccountKeyService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            return await svc.DeleteAsync(id, performedBy, cancellationToken)
                ? Results.NoContent()
                : ApiProblem.NotFound();
        });

        // EST enrollment credentials — the HTTP Basic username/password gate on /simpleenroll.
        var estGroup = v1.MapGroup("/est/enrollment-credentials").RequireAuthorization(AppPermissions.SettingsEdit);

        // A credential's refused logins and enrollments: why a device cannot enroll.
        estGroup.MapGet("/{id:guid}/activity", async (Guid id, Est.IEstCredentialActivityService activity,
            int page = 1, int pageSize = 50, CancellationToken cancellationToken = default) =>
            await activity.GetAsync(id, page, pageSize, cancellationToken) is { } result
                ? Results.Ok(result)
                : ApiProblem.NotFound($"No EST enrollment credential with id {id}."));

        estGroup.MapGet("/", async (Est.IEstEnrollmentCredentialService svc, CancellationToken cancellationToken) =>
            Results.Ok(await svc.GetAllAsync(cancellationToken)));

        estGroup.MapPost("/", async (
            CreateEstEnrollmentCredentialRequest request,
            IValidator<CreateEstEnrollmentCredentialRequest> validator,
            Est.IEstEnrollmentCredentialService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var performedBy = claimsMapper.GetName(httpContext.User);
            try
            {
                var created = await svc.CreateAsync(request.Username, request.Password, performedBy, request.Description, cancellationToken);
                // The password is in this response and nowhere else — nothing reads it back afterwards.
                return Results.Created($"/v1/est/enrollment-credentials/{created.Credential.Id}", created);
            }
            catch (DuplicateEstUsernameException ex)
            {
                return ApiProblem.Conflict(ex.Message);
            }
        });

        estGroup.MapPut("/{id:guid}", async (
            Guid id,
            UpdateEstEnrollmentCredentialRequest request,
            Est.IEstEnrollmentCredentialService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            var updated = await svc.SetEnabledAsync(id, request.IsEnabled, performedBy, cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        });

        estGroup.MapDelete("/{id:guid}", async (
            Guid id,
            Est.IEstEnrollmentCredentialService svc,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var performedBy = claimsMapper.GetName(httpContext.User);
            return await svc.DeleteAsync(id, performedBy, cancellationToken)
                ? Results.NoContent()
                : ApiProblem.NotFound();
        });

        // Audit log — admin only
        var auditGroup = v1.MapGroup("/audit-log").RequireAuthorization("admin-role"); // policy name, not role name

        auditGroup.MapGet("/", async (AuditLogApiService auditSvc, int page = 1, int pageSize = 100, CancellationToken cancellationToken = default) =>
            Results.Ok(await auditSvc.GetAllAsync(page, pageSize, cancellationToken)));

        // The head of every audit chain now; the same data the AuditCheckpoint webhook carries.
        auditGroup.MapGet("/checkpoint", (AuditCheckpointReader checkpoints) => Results.Ok(checkpoints.Read()));

        return endpoints;
    }

    /// <summary>
    /// RFC 6960 responder. Public like <c>/crl</c>: revocation status is what relying parties need
    /// before they trust a certificate, so requiring a token to ask would defeat the point.
    /// </summary>
    private static void MapOcspEndpoints(IEndpointRouteBuilder group, string path)
    {
        // POST carries the DER request as the body; GET carries it base64-encoded in the path, which
        // is what lets a response be cached by URL. RFC 6960 §A.1 defines both.
        group.MapPost(path, async (
            HttpRequest httpRequest,
            CertificateRequestApiService service,
            IIssuerRegistry issuers,
            CancellationToken cancellationToken) =>
        {
            using var buffer = new MemoryStream();
            await httpRequest.Body.CopyToAsync(buffer, cancellationToken);
            return await BuildOcspResponseAsync(buffer.ToArray(), service, issuers, cancellationToken);
        });

        group.MapGet($"{path}/{{encodedRequest}}", async (
            string encodedRequest,
            CertificateRequestApiService service,
            IIssuerRegistry issuers,
            CancellationToken cancellationToken) =>
        {
            byte[] derRequest;
            try
            {
                derRequest = Convert.FromBase64String(Uri.UnescapeDataString(encodedRequest));
            }
            catch (FormatException)
            {
                return OcspMalformed();
            }

            return await BuildOcspResponseAsync(derRequest, service, issuers, cancellationToken);
        });
    }

    private static async Task<IResult> BuildOcspResponseAsync(
        byte[] derRequest,
        CertificateRequestApiService service,
        IIssuerRegistry issuers,
        CancellationToken cancellationToken)
    {
        if (derRequest.Length == 0)
            return OcspMalformed();

        IssuerHandle? issuer;
        IReadOnlyList<string> serials;
        try
        {
            issuer = await issuers.MatchOcspIssuerAsync(derRequest, cancellationToken);
            // No match: answered by the default issuer, every serial unknown — as before for "not ours".
            issuer ??= await issuers.GetDefaultAsync(cancellationToken);
            if (issuer is null || !issuer.CanSignRevocation)
                return Results.Problem("CA certificate not configured.", statusCode: 503);
            serials = issuer.Generator!.ReadOcspRequestSerials(derRequest);
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or InvalidOperationException or Org.BouncyCastle.Ocsp.OcspException)
        {
            return OcspMalformed();
        }

        if (serials.Count == 0)
            return OcspMalformed();

        // Looked up within the signing issuer's rows only: the same serial under another issuer is not ours to answer.
        var statuses = await service.GetRevocationStatusesAsync(serials, issuer.Scope, cancellationToken);
        var response = issuer.Generator.GenerateOcspResponse(derRequest, statuses, await service.GetSettingsAsync(cancellationToken));

        // Not cached: an OCSP answer is per-serial and the response echoes the client's nonce, so a
        // shared cache keyed on anything coarser would hand back someone else's nonce.
        return Results.Bytes(response, OcspResponseContentType);
    }

    private static IResult OcspMalformed() =>
        Results.Bytes(CertificateGenerator.GenerateOcspMalformedRequestResponse(), OcspResponseContentType);

    private static void MapCrlEndpoint(IEndpointRouteBuilder group, string path)
    {
        group.MapGet(path, async (IIssuerRegistry issuers, CrlPublisher publisher, IDistributedCache cache, ILoggerFactory loggerFactory, CancellationToken ct) =>
            await ServeFullCrlAsync(await issuers.ForUnscopedCrlAsync(ct), publisher, cache, loggerFactory.CreateLogger(CrlLoggerCategory), ct));

        group.MapGet($"{path}/{{issuerId:guid}}", async (Guid issuerId, IIssuerRegistry issuers, CrlPublisher publisher, IDistributedCache cache, ILoggerFactory loggerFactory, CancellationToken ct) =>
            await ServeFullCrlAsync(await issuers.GetAsync(new IssuerId(issuerId), ct), publisher, cache, loggerFactory.CreateLogger(CrlLoggerCategory), ct, notFoundWhenMissing: true));
    }

    private const string CrlLoggerCategory = "Qertum.Services.Crl";

    private static async Task<IResult> ServeFullCrlAsync(IssuerHandle? issuer, CrlPublisher publisher, IDistributedCache cache,
        ILogger logger, CancellationToken ct, bool notFoundWhenMissing = false)
    {
        if (issuer is null)
            return notFoundWhenMissing ? ApiProblem.NotFound() : Results.Problem("CA certificate not configured.", statusCode: 503);
        if (issuer.Issuer.Status is IssuerStatus.Archived or IssuerStatus.Destroyed)
            return ApiProblem.NotFound();

        // Offline issuers publish what the operator uploaded (Task 14 fills UploadedCrlDer).
        if (issuer.Issuer.KeyCustody == IssuerKeyCustody.Offline)
            return issuer.Issuer.UploadedCrlDer is { } uploaded
                ? Results.Bytes(uploaded, "application/pkix-crl", "ca.crl")
                : Results.Problem("No CRL has been uploaded for this offline issuer.", statusCode: 503);

        // A cache that cannot be read is a miss: the CRL is rebuilt from the database and still served.
        var cached = await cache.TryGetAsync(CrlCache.KeyFor(issuer.Issuer), logger, ct);
        if (cached is not null)
            return Results.Bytes(cached, "application/pkix-crl", "ca.crl");

        if (!issuer.CanSignRevocation)
            return Results.Problem("This issuer cannot publish a CRL yet.", statusCode: 503);

        var published = await publisher.PublishFullCrlAsync(issuer, tolerateCacheFailure: true, ct);
        return Results.Bytes(published.Bytes, "application/pkix-crl", "ca.crl");
    }

    private static void MapDeltaCrlEndpoint(IEndpointRouteBuilder group, string path)
    {
        // path is "/crl/delta"; per-issuer forms are "/crl/{id}/delta" and "/crl/delta/{id}".
        group.MapGet(path, async (IIssuerRegistry issuers, CertificateRequestApiService service, IssuerCrlState crlState, IDistributedCache cache, ILoggerFactory loggerFactory, CancellationToken ct) =>
            await ServeDeltaCrlAsync(await issuers.ForUnscopedCrlAsync(ct), service, crlState, cache, loggerFactory.CreateLogger(CrlLoggerCategory), ct));
        group.MapGet($"{path}/{{issuerId:guid}}", async (Guid issuerId, IIssuerRegistry issuers, CertificateRequestApiService service, IssuerCrlState crlState, IDistributedCache cache, ILoggerFactory loggerFactory, CancellationToken ct) =>
            await ServeDeltaCrlAsync(await issuers.GetAsync(new IssuerId(issuerId), ct), service, crlState, cache, loggerFactory.CreateLogger(CrlLoggerCategory), ct, notFoundWhenMissing: true));
        var crlRoot = path[..path.LastIndexOf('/')];
        group.MapGet($"{crlRoot}/{{issuerId:guid}}/delta", async (Guid issuerId, IIssuerRegistry issuers, CertificateRequestApiService service, IssuerCrlState crlState, IDistributedCache cache, ILoggerFactory loggerFactory, CancellationToken ct) =>
            await ServeDeltaCrlAsync(await issuers.GetAsync(new IssuerId(issuerId), ct), service, crlState, cache, loggerFactory.CreateLogger(CrlLoggerCategory), ct, notFoundWhenMissing: true));
    }

    private static async Task<IResult> ServeDeltaCrlAsync(IssuerHandle? issuer, CertificateRequestApiService service,
        IssuerCrlState crlState, IDistributedCache cache, ILogger logger, CancellationToken ct, bool notFoundWhenMissing = false)
    {
        if (issuer is null)
            return notFoundWhenMissing ? ApiProblem.NotFound() : Results.Problem("CA certificate not configured.", statusCode: 503);
        if (issuer.Issuer.Status is IssuerStatus.Archived or IssuerStatus.Destroyed || issuer.Issuer.KeyCustody == IssuerKeyCustody.Offline)
            return ApiProblem.NotFound();

        var deltaKey = CrlCache.DeltaKeyFor(issuer.Issuer);
        var deltaBytes = await cache.TryGetAsync(deltaKey, logger, ct);
        if (deltaBytes is not null)
            return Results.Bytes(deltaBytes, "application/pkix-crl", "ca-delta.crl");

        if (!issuer.CanSignRevocation)
            return Results.Problem("CA certificate not configured.", statusCode: 503);

        var settings = await service.GetSettingsAsync(ct);
        if (!settings.DeltaCrlEnabled)
            return Results.Problem("Delta CRL is not enabled.", statusCode: 404);

        // A delta is only meaningful relative to a base; none exists until a full CRL was published.
        var (baseNumber, baseThisUpdate) = await crlState.GetBaseAsync(issuer.Issuer, ct);
        if (baseNumber is not long baseCrlNumber || baseThisUpdate is not DateTime since)
            return Results.Problem("No base CRL has been published yet; fetch the full CRL first.", statusCode: 404);

        var revokedSinceBase = await service.GetRevokedSinceForCrlAsync(since, issuer.Scope, ct);
        var deltaCrlNumber = await crlState.ClaimNextCrlNumberAsync(issuer.Issuer, ct);
        deltaBytes = issuer.Generator!.GenerateDeltaCrl(revokedSinceBase, settings, deltaCrlNumber, baseCrlNumber);

        var cacheHours = settings.DeltaCrlValidityHours > 0 ? settings.DeltaCrlValidityHours : 6;
        await cache.TrySetAsync(deltaKey, deltaBytes,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(cacheHours) }, logger, ct);
        return Results.Bytes(deltaBytes, "application/pkix-crl", "ca-delta.crl");
    }

    /// <summary>
    /// Re-encrypts the Data Protection key ring under <paramref name="targetProvider"/>. Stages
    /// into a sibling directory and only swaps it in once every key-ring file re-encrypts
    /// successfully, so a failure partway through leaves the live key ring exactly as it was.
    /// Note: the swap itself (two directory renames) is not fully transactional — a failure
    /// strictly between the two renames is a narrow, near-instantaneous window this does not
    /// close; see the design doc for the reasoning that this window is acceptable given the
    /// endpoint requires settings.edit and a restart follows regardless.
    /// </summary>
    private static void MigrateSecretStorage(string dataDirectory, Qertum.ServiceDefaults.Secrets.SecretStorageProvider targetProvider)
    {
        var sourceProtector = Qertum.ServiceDefaults.Secrets.SecretProtectorFactory.Create(dataDirectory);

        var keysDir = Path.Combine(dataDirectory, "DataProtection-Keys");
        var stagingDir = Path.Combine(dataDirectory, "DataProtection-Keys.migrating");
        var backupDir = Path.Combine(dataDirectory, "DataProtection-Keys.bak");

        if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true);
        Directory.CreateDirectory(stagingDir);

        // Write the new provider's config into a *separate* temp data directory so
        // SecretProtectorFactory.Create resolves the target provider without touching the live
        // secret-storage.json yet.
        var stagingConfigDir = Path.Combine(dataDirectory, "secret-storage.migrating");
        if (Directory.Exists(stagingConfigDir)) Directory.Delete(stagingConfigDir, recursive: true);
        Directory.CreateDirectory(stagingConfigDir);
        Qertum.ServiceDefaults.Secrets.SecretStorageConfig.Write(stagingConfigDir, targetProvider);
        var targetProtector = Qertum.ServiceDefaults.Secrets.SecretProtectorFactory.Create(stagingConfigDir);

        var sourceEncryptor = new Qertum.Services.DataProtection.SecretProtectorXmlEncryptor(sourceProtector);
        var targetEncryptor = new Qertum.Services.DataProtection.SecretProtectorXmlEncryptor(targetProtector);

        if (Directory.Exists(keysDir))
        {
            foreach (var file in Directory.EnumerateFiles(keysDir, "*.xml"))
            {
                // Rewrite in place on the loaded tree: the file's outer <key> structure
                // (id/creationDate/descriptor) must survive unchanged — only the inner
                // <encryptedSecret> payload gets re-encrypted under the new provider. Dumping raw
                // re-encrypted bytes over the whole file (the previous approach) destroyed that
                // outer XML, so XmlKeyManager could no longer parse the file at all.
                var xml = System.Xml.Linq.XElement.Load(file);
                var encryptedSecret = xml.Descendants("encryptedSecret").SingleOrDefault();
                if (encryptedSecret is not null)
                {
                    var plaintextElement = sourceEncryptor.Decrypt(encryptedSecret);
                    var reencrypted = targetEncryptor.Encrypt(plaintextElement);
                    encryptedSecret.ReplaceWith(reencrypted.EncryptedElement);
                }
                xml.Save(Path.Combine(stagingDir, Path.GetFileName(file)));
            }
        }

        // Atomic-ish swap: two renames. If the second fails, the backup still exists and the
        // live directory is either the original (first rename didn't happen) or missing
        // (mid-swap) — see the doc comment above.
        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);
        if (Directory.Exists(keysDir))
            Directory.Move(keysDir, backupDir);
        Directory.Move(stagingDir, keysDir);

        Qertum.ServiceDefaults.Secrets.SecretStorageConfig.Write(dataDirectory, targetProvider);

        Directory.Delete(stagingConfigDir, recursive: true);
        if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true);
    }

    /// <summary>
    /// Force replace destroys the current CA's key, so beyond <c>settings.edit</c> it needs the admin
    /// role (like permission grants) and the exact confirmation text naming the CA it destroys.
    /// </summary>
    private static async Task<IResult?> ForceGuardAsync(IAuthorizationService authorization, HttpContext httpContext,
        IssuerHandle current, string? confirm)
    {
        if (!(await authorization.AuthorizeAsync(httpContext.User, "admin-role")).Succeeded)
            return Results.Forbid();
        var expected = IssuerLifecycleService.ForceConfirmation(current.Issuer);
        return string.Equals(confirm, expected, StringComparison.Ordinal)
            ? null
            : ApiProblem.BadRequest($"Replacing the CA destroys its key. Type exactly \"{expected}\" in confirm to proceed.");
    }

    /// <summary>
    /// Checks an about-to-be-imported CA certificate against the CA default <see cref="CaSettings.PqcStage"/>.
    /// Returns <see langword="null"/> when the import may proceed, or a 400 <see cref="IResult"/> to
    /// return immediately otherwise. Split out from the `/ca/import` handler so it is unit-testable
    /// without an HTTP fixture.
    /// </summary>
    internal static IResult? ValidateImportAlgorithmPolicy(CaSettings settings, string certificatePem)
    {
        try
        {
            var importedAlgorithm = CertificateGenerator.DetectAlgorithmFromCertificatePem(certificatePem);
            if (!importedAlgorithm.CanSign())
                return ApiProblem.BadRequest(
                    $"The imported certificate's key is '{importedAlgorithm.ToCanonicalString()}', a key encapsulation " +
                    "key; it cannot sign, so it cannot be a CA key.");
            // A CA key has no template, so the CA default stage governs and no exception applies.
            var pqcVerdict = PqcStageEvaluator.Evaluate(settings.PqcStage, importedAlgorithm, isRenewal: false);
            if (pqcVerdict.Outcome == PqcOutcome.Refused)
                return ApiProblem.BadRequest(pqcVerdict.Reason!);
        }
        // NotSupportedException: the certificate parsed but carries a key type this CA cannot issue
        // for. That is a client-supplied-input problem like an unparseable PEM, so it answers 400
        // rather than escaping the endpoint as a 500.
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            return ApiProblem.BadRequest(ex.Message);
        }

        return null;
    }
}

internal static class ValidationResultExtensions
{
    internal static IDictionary<string, string[]> ToErrorDictionary(this ValidationResult result) =>
        result.Errors
            .GroupBy(e => e.PropertyName)
            .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray());
}

public sealed class CertificateRequestApiService(
    ICertificateRequestService certificateRequestService,
    Policies.ICertificateRequestPreviewService previewService)
{
    public Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRevocationStatusesAsync(serialNumbers, cancellationToken);

    public Task<PagedResult<CertificateRequest>> GetAllAsync(int page = 1, int pageSize = 100,
        CertificateRequestStatus? status = null, string? search = null, CancellationToken cancellationToken = default)
        => certificateRequestService.GetAllAsync(page, pageSize, status, search, cancellationToken);

    public Task<CertificateRequestStatusCounts> GetStatusCountsAsync(string? search = null, CancellationToken cancellationToken = default)
        => certificateRequestService.GetStatusCountsAsync(search, cancellationToken);

    public Task<PagedResult<CertificateRequest>> GetIssuedAsync(int page = 1, int pageSize = 100,
        IssuedCertificateFilter? filter = null, string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
        => certificateRequestService.GetIssuedAsync(page, pageSize, filter, search, validOnly, cancellationToken);

    public Task<IssuedCertificateCounts> GetIssuedValidityCountsAsync(string? search = null, bool validOnly = false, CancellationToken cancellationToken = default)
        => certificateRequestService.GetIssuedValidityCountsAsync(search, validOnly, cancellationToken);

    public Task<PagedResult<CertificateRequest>> GetRejectedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRejectedAsync(page, pageSize, cancellationToken);

    public Task<PagedResult<CertificateRequest>> GetRevokedAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRevokedAsync(page, pageSize, cancellationToken);

    public Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(CancellationToken cancellationToken = default)
        => certificateRequestService.GetAllRevokedForCrlAsync(cancellationToken);

    public Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRevokedSinceForCrlAsync(sinceUtc, cancellationToken);

    public Task<IReadOnlyList<CertificateRequest>> GetRevokedSinceForCrlAsync(DateTime sinceUtc, IssuerScope scope, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRevokedSinceForCrlAsync(sinceUtc, scope, cancellationToken);

    public Task<IReadOnlyList<CertificateRequest>> GetAllRevokedForCrlAsync(IssuerScope scope, CancellationToken cancellationToken = default)
        => certificateRequestService.GetAllRevokedForCrlAsync(scope, cancellationToken);

    public Task<IReadOnlyDictionary<string, OcspCertificateStatus>> GetRevocationStatusesAsync(
        IReadOnlyCollection<string> serialNumbers, IssuerScope scope, CancellationToken cancellationToken = default)
        => certificateRequestService.GetRevocationStatusesAsync(serialNumbers, scope, cancellationToken);

    public Task RecordBaseCrlAsync(long crlNumber, DateTime thisUpdateUtc, CancellationToken cancellationToken = default)
        => certificateRequestService.RecordBaseCrlAsync(crlNumber, thisUpdateUtc, cancellationToken);

    public Task<PagedResult<CertificateRequest>> GetExpiredAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
        => certificateRequestService.GetExpiredAsync(page, pageSize, cancellationToken);

    public Task<CaSettings> SetPqcStageAsync(PqcStage stage, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetPqcStageAsync(stage, performedBy, cancellationToken);

    public Task<CaSettings> SetRevokedIssuerModeAsync(RevokedIssuerMode mode, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetRevokedIssuerModeAsync(mode, performedBy, cancellationToken);

    public Task<CaSettings> SetIssuerStrengthAsync(IssuerStrengthMode mode, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetIssuerStrengthAsync(mode, performedBy, cancellationToken);

    public Task<CaSettings> SetCaApprovalRuleAsync(bool requireIndependent, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetCaApprovalRuleAsync(requireIndependent, performedBy, cancellationToken);

    public Task<CaSettings> SetTwoPersonApprovalAsync(bool enabled, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetTwoPersonApprovalAsync(enabled, performedBy, cancellationToken);

    public Task<CertificateRequest?> GetByIdAsync(CertificateRequestId id, CancellationToken cancellationToken = default)
        => certificateRequestService.GetByIdAsync(id, cancellationToken);

    public Task<CertificateRequest> CreateAsync(CreateCertificateRequestRequest request, string performedBy, string? requestedBySubject = null, CancellationToken cancellationToken = default)
        => CreateAsync(request, performedBy, requestedBySubject, requester: null, cancellationToken);

    public Task<CertificateRequest> CreateAsync(CreateCertificateRequestRequest request, string performedBy, string? requestedBySubject, Policies.RequesterRoles? requester, CancellationToken cancellationToken = default)
        => CreateAsync(request, performedBy, requestedBySubject, requester, caller: null, cancellationToken);

    public Task<CertificateRequest> CreateAsync(CreateCertificateRequestRequest request, string performedBy, string? requestedBySubject, Policies.RequesterRoles? requester, Policies.CallerContext? caller, CancellationToken cancellationToken = default)
    {
        return certificateRequestService.CreateAsync(new CertificateRequest
        {
            CommonName = request.CommonName,
            // Both attribution and ownership come from the caller's token, never from the request
            // body, so a caller cannot file a request in someone else's name.
            RequestedBy = performedBy,
            RequestedBySubject = requestedBySubject,
            Type = request.Type,
            PropertiesJson = request.PropertiesJson,
            // Never taken from the body: a caller-chosen status would let certificates.create skip
            // approval entirely.
            Status = CertificateRequestStatus.Pending,
            KeyAlgorithm = request.KeyAlgorithm,
            ValidityDays = request.ValidityDays,
            Metadata = request.Metadata?.Normalize() ?? new CertificateMetadata()
        }, performedBy, autoApprovalSetting: null, requester, caller, cancellationToken);
    }

    /// <summary>
    /// Dry-runs <see cref="CreateAsync"/> against the same payload. Builds the candidate exactly as
    /// CreateAsync does — including the Pending status and the refusal to read the requester from
    /// the body — so the preview describes the request that would actually be filed.
    /// </summary>
    public Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CreateCertificateRequestRequest request, CancellationToken cancellationToken = default)
        => PreviewCreateAsync(request, requester: null, caller: null, cancellationToken);

    public Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CreateCertificateRequestRequest request, Policies.RequesterRoles? requester, CancellationToken cancellationToken = default)
        => PreviewCreateAsync(request, requester, caller: null, cancellationToken);

    public Task<CertificateRequestPreviewResponse> PreviewCreateAsync(
        CreateCertificateRequestRequest request, Policies.RequesterRoles? requester, Policies.CallerContext? caller, CancellationToken cancellationToken = default)
    {
        return previewService.PreviewCreateAsync(new CertificateRequest
        {
            CommonName = request.CommonName,
            Type = request.Type,
            PropertiesJson = request.PropertiesJson,
            Status = CertificateRequestStatus.Pending,
            KeyAlgorithm = request.KeyAlgorithm,
            ValidityDays = request.ValidityDays
        }, requester, caller, cancellationToken);
    }

    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, UpdateCertificateRequestRequest request, string performedBy, CancellationToken cancellationToken = default)
        => UpdateAsync(id, request, performedBy, requester: null, cancellationToken);

    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, UpdateCertificateRequestRequest request, string performedBy, Policies.RequesterRoles? requester, CancellationToken cancellationToken = default)
        => UpdateAsync(id, request, performedBy, requester, caller: null, cancellationToken);

    public Task<CertificateRequest?> UpdateAsync(CertificateRequestId id, UpdateCertificateRequestRequest request, string performedBy, Policies.RequesterRoles? requester, Policies.CallerContext? caller, CancellationToken cancellationToken = default)
    {
        return certificateRequestService.UpdateAsync(id, new CertificateRequest
        {
            CommonName = request.CommonName,
            Type = request.Type,
            PropertiesJson = request.PropertiesJson,
            Status = request.Status,
            KeyAlgorithm = request.KeyAlgorithm,
            ValidityDays = request.ValidityDays
        }, performedBy, requester, caller, cancellationToken);
    }

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.MarkAsApprovedAsync(id, performedBy, cancellationToken);

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Policies.ApprovalPreviewReport? previewReport, CancellationToken cancellationToken = default)
        => certificateRequestService.MarkAsApprovedAsync(id, performedBy, previewReport, cancellationToken);

    public Task<CertificateRequest?> MarkAsApprovedAsync(CertificateRequestId id, string performedBy, Policies.ApprovalPreviewReport? previewReport, Policies.CallerContext? caller, CancellationToken cancellationToken)
        => certificateRequestService.MarkAsApprovedAsync(id, performedBy, previewReport, caller, cancellationToken);

    public Task<ApprovalPreviewResponse> PreviewApprovalAsync(CertificateRequest pending, string performedBy, CancellationToken cancellationToken = default)
        => previewService.PreviewApprovalAsync(pending, performedBy, cancellationToken);

    public Task<ApprovalPreviewResponse> PreviewApprovalAsync(CertificateRequest pending, string performedBy, Policies.CallerContext? caller, CancellationToken cancellationToken)
        => previewService.PreviewApprovalAsync(pending, performedBy, caller, cancellationToken);

    public Task<CertificateRequest?> MarkAsRejectedAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.MarkAsRejectedAsync(id, performedBy, cancellationToken);

    public Task<CertificateRequest?> MarkAsPendingRevocationAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.MarkAsPendingRevocationAsync(id, reason, performedBy, cancellationToken);

    public Task<CertificateRequest?> MarkAsRevokedAsync(CertificateRequestId id, string? reason, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.MarkAsRevokedAsync(id, reason, performedBy, cancellationToken);

    public Task<CertificateRequest?> UpdateMetadataAsync(CertificateRequestId id, CertificateMetadata metadata, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.UpdateMetadataAsync(id, metadata, performedBy, cancellationToken);

    public Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.RenewAsync(id, performedBy, cancellationToken);

    public Task<CertificateRequest?> RenewAsync(CertificateRequestId id, string performedBy, Policies.CallerContext? caller, CancellationToken cancellationToken = default)
        => certificateRequestService.RenewAsync(id, performedBy, caller, cancellationToken);

    public Task<bool> DeleteAsync(CertificateRequestId id, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.DeleteAsync(id, performedBy, cancellationToken);

    public Task<CertificateDashboardSummary> GetDashboardSummaryAsync(CancellationToken cancellationToken = default)
        => certificateRequestService.GetDashboardSummaryAsync(cancellationToken);

    public Task<CaSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
        => certificateRequestService.GetSettingsAsync(cancellationToken);

    public Task<CaSettings> SetupOrUpdateSettingsAsync(CaSettings settings, string performedBy, CancellationToken cancellationToken = default)
        => certificateRequestService.SetupOrUpdateSettingsAsync(settings, performedBy, cancellationToken);

    public Task<long> ClaimNextCrlNumberAsync(CancellationToken cancellationToken = default)
        => certificateRequestService.ClaimNextCrlNumberAsync(cancellationToken);

    public Task<Guid?> GetPendingRootCaRequestIdAsync(CancellationToken cancellationToken = default)
        => certificateRequestService.GetPendingRootCaRequestIdAsync(cancellationToken);

    public Task<CertificateRequest> CreateRootCaRequestAsync(string commonName, CertificateKeyAlgorithm algorithm, string propertiesJson, string performedBy, string? requestedBySubject = null, CancellationToken cancellationToken = default)
        => certificateRequestService.CreateAsync(new CertificateRequest
        {
            CommonName = commonName,
            RequestedBy = performedBy,
            RequestedBySubject = requestedBySubject,
            Type = WellKnownCertificateTypes.RootCa,
            PropertiesJson = propertiesJson,
            Status = CertificateRequestStatus.Pending,
            KeyAlgorithm = algorithm
        }, performedBy, cancellationToken);
}

public sealed class RolePermissionsApiService(IRolePermissionService rolePermissionService)
{
    public Task<IReadOnlyDictionary<string, IReadOnlyList<string>>> GetAllAsync(CancellationToken cancellationToken = default)
        => rolePermissionService.GetAllRolePermissionsAsync(cancellationToken);

    public Task<RolePermissionChange> SetAsync(string role, IEnumerable<string> permissions, string performedBy, CancellationToken cancellationToken = default)
        => rolePermissionService.SetPermissionsForRoleAsync(role, permissions, performedBy, cancellationToken);
}

public sealed class AuditLogApiService(IAuditLogService auditLogService)
{
    public Task<IReadOnlyList<AuditLogEntry>> GetAllAsync(int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
        => auditLogService.GetAllAsync(page, pageSize, cancellationToken);
}

public sealed class CertificateTemplateApiService(ICertificateTemplateService templateService)
{
    public Task<IReadOnlyList<CertificateTemplate>> GetAllAsync(CancellationToken cancellationToken = default)
        => templateService.GetAllAsync(cancellationToken);
}
