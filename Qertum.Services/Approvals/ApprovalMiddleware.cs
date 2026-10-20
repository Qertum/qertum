using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Qertum.Services.Auth;

namespace Qertum.Services.Approvals;

/// <summary>
/// With two-person approval on, refuses a gated operation (<see cref="ApprovalRoutes"/>) unless the caller holds an approved,
/// unexpired grant for it, which it uses up before the handler runs and gives back when the handler answers 400 or above.
/// Runs after authorization and step-up: a caller without the permission has already been answered 403, and a missing
/// second factor has already been challenged.
/// </summary>
public sealed class ApprovalMiddleware(RequestDelegate next)
{
    /// <summary>Applies the check to the matched endpoint, then continues.</summary>
    public async Task InvokeAsync(
        HttpContext context, IApprovalService approvals, CertificateRequestDbContext db,
        IIdentityClaimsMapper claims, IAuthorizationService authorization,
        IAuditLogService auditLog, IWebhookService webhooks, ILogger<ApprovalMiddleware> logger)
    {
        if (context.GetEndpoint() is not RouteEndpoint endpoint
            || ApprovalRoutes.Find(context.Request.Method, endpoint.RoutePattern.RawText) is not { } entry)
        {
            await next(context);
            return;
        }

        var ct = context.RequestAborted;
        if (!await approvals.IsEnabledAsync(ct))
        {
            await next(context);
            return;
        }

        var subject = claims.GetSubject(context.User);
        var targetId = entry.Operation == ApprovalOperations.IssuerCreateIntermediate
            ? null
            : ApprovalTargets.Normalize(context.GetRouteValue("id")?.ToString());

        if (!await AppliesAsync(entry, targetId, context, db, claims, authorization, subject, ct))
        {
            await next(context);
            return;
        }

        var granted = subject is null ? null : await approvals.ClaimAsync(subject, entry.Operation, targetId, ct);
        if (granted is not { } grant)
        {
            logger.LogInformation("Approval required for {Operation} on {Target}.", entry.Operation, targetId ?? "-");
            await Results.Problem(
                title: "Approval required",
                detail: "A second administrator must approve this operation first. Request an approval, wait for it to be granted, then repeat the operation within its time window.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["operation"] = entry.Operation, ["targetId"] = targetId })
                .ExecuteAsync(context);
            return;
        }

        // A typo or a refused input must not cost an approval: give the grant back when the handler fails. The use is
        // reported only once the handler succeeded, so a grant released and used again is reported once.
        context.Response.OnStarting(async () =>
        {
            if (context.Response.StatusCode >= StatusCodes.Status400BadRequest)
            {
                await approvals.ReleaseAsync(grant, CancellationToken.None);
                return;
            }

            // The operation has already happened: a failure to report it must not turn its answer into an error.
            try
            {
                if (await approvals.GetAsync(grant, CancellationToken.None) is { } used)
                    await ApprovalNotifications.PublishAsync(auditLog, webhooks, WellKnownWebhookEvents.ApprovalUsed,
                        claims.GetName(context.User), used, ApprovalStatus.Used, CancellationToken.None);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Could not record the use of approval {Approval}.", grant);
            }
        });
        await next(context);
    }

    private static async Task<bool> AppliesAsync(
        ApprovalRouteEntry entry, string? targetId, HttpContext context, CertificateRequestDbContext db,
        IIdentityClaimsMapper claims, IAuthorizationService authorization, string? subject, CancellationToken ct)
    {
        switch (entry.Gate)
        {
            case ApprovalGate.Always:
                return true;

            case ApprovalGate.NonOwnerKeyAccess:
            {
                // Only an administrator can reach someone else's key; anyone else is answered by the handler.
                if (!claims.IsAdmin(context.User) || !Guid.TryParse(targetId, out var id))
                    return false;
                var request = await db.CertificateRequests.AsNoTracking().Where(r => r.Id == new CertificateRequestId(id))
                    .Select(r => new { r.RequestedBySubject }).FirstOrDefaultAsync(ct);
                if (request is null)
                    return false;
                var owner = !string.IsNullOrWhiteSpace(request.RequestedBySubject)
                    && string.Equals(request.RequestedBySubject, subject, StringComparison.Ordinal);
                return !owner;
            }

            case ApprovalGate.BulkRevokeOnly:
            {
                if (!Guid.TryParse(targetId, out var id))
                    return false;
                var operation = await db.BulkOperations.AsNoTracking().Where(o => o.Id == new BulkOperationId(id))
                    .Select(o => new { o.Kind, o.CreatedBy, o.CreatedBySubject }).FirstOrDefaultAsync(ct);
                if (operation is not { Kind: BulkOperationKind.Revoke })
                    return false;
                // The handler hides another person's operation (404) and refuses a caller without the permission (403);
                // neither is for this middleware to pre-empt or to confirm exists.
                var name = claims.GetName(context.User);
                var sees = claims.IsAdmin(context.User)
                    || (operation.CreatedBySubject is { } createdBy
                        ? string.Equals(createdBy, subject, StringComparison.Ordinal)
                        : string.Equals(operation.CreatedBy, name, StringComparison.Ordinal));
                return sees && (await authorization.AuthorizeAsync(context.User, context, AppPermissions.CertificatesManage)).Succeeded;
            }

            default:
                return false;
        }
    }
}

/// <summary>Pipeline registration for <see cref="ApprovalMiddleware"/>.</summary>
public static class ApprovalApplicationBuilderExtensions
{
    /// <summary>Adds the approval check. Call it right after <c>UseQertumStepUp()</c>.</summary>
    public static IApplicationBuilder UseQertumApprovals(this IApplicationBuilder app) => app.UseMiddleware<ApprovalMiddleware>();
}
