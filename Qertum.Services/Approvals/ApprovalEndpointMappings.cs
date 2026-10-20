using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services.Auth;

namespace Qertum.Services.Approvals;

/// <summary>REST surface of two-person approval under <c>/v1/approvals</c>.</summary>
public static class ApprovalEndpointMappings
{
    /// <summary>
    /// Maps the group. Any signed-in caller reaches it: a request is checked against the permission its operation needs,
    /// a decision against the administrator role, and a read against ownership.
    /// </summary>
    /// <param name="v1">The <c>/v1</c> group.</param>
    /// <returns>The same group.</returns>
    public static RouteGroupBuilder MapApprovalApi(this RouteGroupBuilder v1)
    {
        var group = v1.MapGroup("/approvals").WithTags("Approvals").RequireAuthorization();

        group.MapPost("/", async (
            RequestApprovalRequest body, IApprovalService approvals, CertificateRequestDbContext db,
            ICertificateAccessEvaluator accessEvaluator, IAuthorizationService authorization,
            IAuditLogService auditLog, IWebhookService webhooks,
            HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            if (!ApprovalOperations.IsKnown(body.Operation))
                return ApiProblem.BadRequest("operation is not one that needs approval.");

            var target = body.TargetId?.Trim();
            if (await MayPerformAsync(body.Operation, target, db, accessEvaluator, authorization, claims, http, ct) is { } refusal)
                return refusal;
            var label = await ApprovalTargets.LabelAsync(db, body.Operation, target, ct);
            if (ApprovalOperations.NeedsTarget(body.Operation) && label is null)
                return ApiProblem.NotFound("The target does not exist.");

            try
            {
                var request = await approvals.RequestAsync(CallerOf(http, claims), body.Operation, target, body.Note, ct);
                await ApprovalNotifications.PublishAsync(auditLog, webhooks, WellKnownWebhookEvents.ApprovalRequested,
                    claims.GetName(http.User), request, ApprovalStatus.Pending, ct);
                return Results.Created($"/v1/approvals/{request.Id}", Response(request, approvals, label, claims.GetSubject(http.User)));
            }
            catch (ApprovalException ex) { return Problem(ex); }
        });

        group.MapPost("/{id:guid}/approve", (Guid id, DecideApprovalRequest? body, IApprovalService approvals, CertificateRequestDbContext db,
            IAuditLogService auditLog, IWebhookService webhooks, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct)
            => DecideAsync(id, approve: true, body, approvals, db, auditLog, webhooks, http, claims, ct));

        group.MapPost("/{id:guid}/deny", (Guid id, DecideApprovalRequest? body, IApprovalService approvals, CertificateRequestDbContext db,
            IAuditLogService auditLog, IWebhookService webhooks, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct)
            => DecideAsync(id, approve: false, body, approvals, db, auditLog, webhooks, http, claims, ct));

        group.MapGet("/", async (
            [FromQuery] ApprovalStatus? status, [FromQuery] bool? mine, [FromQuery] int? page, [FromQuery] int? pageSize,
            IApprovalService approvals, CertificateRequestDbContext db, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var result = await approvals.ListAsync(CallerOf(http, claims), status, mine ?? false, page ?? 1, pageSize ?? 50, ct);
            var items = new List<ApprovalResponse>();
            foreach (var request in result.Items)
                items.Add(Response(request, approvals, await ApprovalTargets.LabelAsync(db, request.Operation, request.TargetId, ct), claims.GetSubject(http.User)));
            return Results.Ok(new PagedResult<ApprovalResponse>
            {
                Items = items, TotalCount = result.TotalCount, Page = result.Page, PageSize = result.PageSize
            });
        });

        group.MapGet("/{id:guid}", async (Guid id, IApprovalService approvals, CertificateRequestDbContext db,
            HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var request = await approvals.GetAsync(new ApprovalRequestId(id), ct);
            var caller = CallerOf(http, claims);
            // Another person's request is not confirmed to exist.
            if (request is null || (!caller.IsAdmin && request.RequestedBySubject != caller.Subject))
                return ApiProblem.NotFound();
            return Results.Ok(Response(request, approvals, await ApprovalTargets.LabelAsync(db, request.Operation, request.TargetId, ct), caller.Subject));
        });

        return v1;
    }

    private static async Task<IResult> DecideAsync(
        Guid id, bool approve, DecideApprovalRequest? body, IApprovalService approvals, CertificateRequestDbContext db,
        IAuditLogService auditLog, IWebhookService webhooks, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct)
    {
        try
        {
            var request = await approvals.DecideAsync(new ApprovalRequestId(id), CallerOf(http, claims), approve, body?.Note, ct);
            await ApprovalNotifications.PublishAsync(auditLog, webhooks,
                approve ? WellKnownWebhookEvents.ApprovalApproved : WellKnownWebhookEvents.ApprovalDenied,
                claims.GetName(http.User), request, request.Status, ct);
            return Results.Ok(Response(request, approvals, await ApprovalTargets.LabelAsync(db, request.Operation, request.TargetId, ct), claims.GetSubject(http.User)));
        }
        catch (ApprovalException ex) { return Problem(ex); }
    }

    /// <summary>Null when the caller may perform the operation (as far as a request can tell), else the refusal.</summary>
    private static async Task<IResult?> MayPerformAsync(
        string operation, string? target, CertificateRequestDbContext db, ICertificateAccessEvaluator accessEvaluator,
        IAuthorizationService authorization, IIdentityClaimsMapper claims, HttpContext http, CancellationToken ct)
    {
        switch (operation)
        {
            case ApprovalOperations.KeyExport:
            case ApprovalOperations.PfxExport:
            {
                if (!Guid.TryParse(target, out var id))
                    return ApiProblem.NotFound("The target does not exist.");
                var request = await db.CertificateRequests.AsNoTracking().FirstOrDefaultAsync(r => r.Id == new CertificateRequestId(id), ct);
                if (request is null)
                    return ApiProblem.NotFound("The target does not exist.");
                return accessEvaluator.CanAccessPrivateKey(http.User, request) ? null : Results.Forbid();
            }

            case ApprovalOperations.BulkRevoke:
                return (await authorization.AuthorizeAsync(http.User, http, AppPermissions.CertificatesManage)).Succeeded ? null : Results.Forbid();

            case ApprovalOperations.PolicyPublish:
                return (await authorization.AuthorizeAsync(http.User, http, AppPermissions.PoliciesPublish)).Succeeded ? null : Results.Forbid();

            default:
                return claims.IsAdmin(http.User) ? null : Results.Forbid();
        }
    }

    private static ApprovalCaller CallerOf(HttpContext http, IIdentityClaimsMapper claims) =>
        new(claims.GetSubject(http.User), claims.GetName(http.User), claims.IsAdmin(http.User));

    private static ApprovalResponse Response(ApprovalRequest r, IApprovalService approvals, string? label, string? callerSubject) => new(
        r.Id, r.Operation, r.TargetId, label, r.Note, r.RequestedByName, r.RequestedAtUtc, approvals.EffectiveStatus(r),
        r.DecidedByName, r.DecidedAtUtc, r.DecisionNote, r.GrantExpiresAtUtc, r.UsedAtUtc,
        IsMine: callerSubject is not null && r.RequestedBySubject == callerSubject);

    private static IResult Problem(ApprovalException ex) => ex.Error switch
    {
        ApprovalError.NotAllowed => Results.Problem(title: "Not allowed", detail: ex.Message, statusCode: StatusCodes.Status403Forbidden),
        ApprovalError.NotFound => ApiProblem.NotFound(ex.Message),
        ApprovalError.Conflict => ApiProblem.Conflict(ex.Message),
        _ => ApiProblem.BadRequest(ex.Message)
    };
}
