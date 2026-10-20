using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Auth;
using Qertum.Services.Policies;

namespace Qertum.Services.BulkOperations;

/// <summary>REST surface of bulk revoke and renew under <c>/v1/bulk-operations</c>.</summary>
public static class BulkOperationEndpointMappings
{
    /// <summary>Maps the group. Any signed-in caller reaches it; each handler checks the permission its operation's kind needs.</summary>
    /// <param name="v1">The <c>/v1</c> group.</param>
    /// <returns>The same group.</returns>
    public static RouteGroupBuilder MapBulkOperationApi(this RouteGroupBuilder v1)
    {
        var group = v1.MapGroup("/bulk-operations").WithTags("BulkOperations").RequireAuthorization().RequireRateLimiting("api");

        group.MapPost("/preview", async (PreviewBulkOperationRequest request, IValidator<PreviewBulkOperationRequest> validator,
            IBulkOperationService service, IAuthorizationService authorization, HttpContext http,
            IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct) =>
        {
            var validation = await validator.ValidateAsync(request, ct);
            if (!validation.IsValid) return Results.ValidationProblem(validation.ToDictionary());
            if (await Forbidden(request.Kind, authorization, http) is { } forbidden) return forbidden;
            try
            {
                var preview = await service.PreviewAsync(request, await ActorOf(http, claims, callers, ct), ct);
                return Results.Created($"/v1/bulk-operations/{preview.Operation.Id}", preview);
            }
            catch (BulkOperationException ex) { return Problem(ex); }
        });

        group.MapPost("/{id:guid}/execute", async (Guid id, ExecuteBulkOperationRequest request, IValidator<ExecuteBulkOperationRequest> validator,
            IBulkOperationService service, IAuthorizationService authorization, HttpContext http,
            IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct) =>
        {
            var validation = await validator.ValidateAsync(request, ct);
            if (!validation.IsValid) return Results.ValidationProblem(validation.ToDictionary());
            var actor = await ActorOf(http, claims, callers, ct);
            var gate = await Visible(id, actor, service, authorization, http, ct);
            if (gate.Failure is not null) return gate.Failure;
            try
            {
                var view = await service.ExecuteAsync(new BulkOperationId(id), request.ConfirmCount, actor, ct);
                http.Response.Headers.RetryAfter = ProgressHints.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return Results.Accepted($"/v1/bulk-operations/{id}", view);
            }
            catch (BulkOperationException ex) { return Problem(ex); }
        });

        group.MapPost("/{id:guid}/cancel", async (Guid id, IBulkOperationService service, IAuthorizationService authorization,
            HttpContext http, IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct) =>
        {
            var actor = await ActorOf(http, claims, callers, ct);
            var gate = await Visible(id, actor, service, authorization, http, ct);
            if (gate.Failure is not null) return gate.Failure;
            try { return Results.Ok(await service.CancelAsync(new BulkOperationId(id), actor, ct)); }
            catch (BulkOperationException ex) { return Problem(ex); }
        });

        group.MapGet("/", async (IBulkOperationService service, HttpContext http, IIdentityClaimsMapper claims,
            ICallerContextResolver callers, CancellationToken ct, int page = 1, int pageSize = 50) =>
        {
            var actor = await ActorOf(http, claims, callers, ct);
            // Own operations only, unless admin. A caller with no subject sees nothing rather than everything.
            var subject = actor.IsAdmin ? null : actor.Subject ?? Guid.NewGuid().ToString("N");
            return Results.Ok(await service.ListAsync(page, pageSize, subject, ct));
        });

        group.MapGet("/{id:guid}", async (Guid id, IBulkOperationService service, IAuthorizationService authorization,
            HttpContext http, IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct) =>
        {
            var gate = await Visible(id, await ActorOf(http, claims, callers, ct), service, authorization, http, ct);
            if (gate.Failure is not null) return gate.Failure;
            if (gate.Operation!.Status == BulkOperationStatus.Running)
                http.Response.Headers.RetryAfter = ProgressHints.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Results.Ok(gate.Operation);
        });

        group.MapGet("/{id:guid}/items", async (Guid id, IBulkOperationService service, IAuthorizationService authorization,
            HttpContext http, IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct,
            BulkItemOutcome? outcome = null, int page = 1, int pageSize = 100) =>
        {
            var gate = await Visible(id, await ActorOf(http, claims, callers, ct), service, authorization, http, ct);
            if (gate.Failure is not null) return gate.Failure;
            return Results.Ok(await service.GetItemsAsync(new BulkOperationId(id), outcome, page, pageSize, ct));
        });

        return v1;
    }

    private static Task<BulkActor> ActorOf(HttpContext http, IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct) =>
        ResolveAsync(http, claims, callers, ct);

    private static async Task<BulkActor> ResolveAsync(HttpContext http, IIdentityClaimsMapper claims, ICallerContextResolver callers, CancellationToken ct)
    {
        var caller = await callers.ResolveAsync(claims.GetSubject(http.User), claims.GetName(http.User), [.. claims.GetRoles(http.User)], ct);
        return new BulkActor(caller.Subject, caller.Name, caller.IsAdmin, caller.HoldsCaPermission);
    }

    private static async Task<IResult?> Forbidden(BulkOperationKind kind, IAuthorizationService authorization, HttpContext http)
    {
        var permission = BulkOperationAccess.PermissionFor(kind);
        return (await authorization.AuthorizeAsync(http.User, http, permission)).Succeeded
            ? null
            : Results.Problem(detail: $"This needs the {permission} permission.", statusCode: StatusCodes.Status403Forbidden, title: "Forbidden");
    }

    /// <summary>404 for an unknown operation or one the caller may not see (existence is not confirmed); 403 when the kind's permission is missing.</summary>
    private static async Task<(BulkOperationView? Operation, IResult? Failure)> Visible(Guid id, BulkActor actor,
        IBulkOperationService service, IAuthorizationService authorization, HttpContext http, CancellationToken ct)
    {
        var operation = await service.GetAsync(new BulkOperationId(id), ct);
        if (operation is null || !BulkOperationAccess.CanSee(operation, actor))
            return (null, ApiProblem.NotFound("No such bulk operation."));
        return (operation, await Forbidden(operation.Kind, authorization, http));
    }

    private static IResult Problem(BulkOperationException ex) => ex.StatusCode switch
    {
        404 => ApiProblem.NotFound(ex.Detail),
        409 => ApiProblem.Conflict(ex.Detail),
        410 => Results.Problem(detail: ex.Detail, statusCode: StatusCodes.Status410Gone, title: "Gone"),
        _ => Results.Problem(detail: ex.Detail, statusCode: StatusCodes.Status422UnprocessableEntity, title: "Unprocessable Entity")
    };
}
