using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Auth;

namespace Qertum.Services;

/// <summary>Routes for PQC exceptions. Admin only, reads included: a grantable permission would let its holder grant itself one.</summary>
public static class PqcEndpointMappings
{
    /// <summary>Maps <c>/pqc-exceptions</c> under the <c>/v1</c> group.</summary>
    public static IEndpointRouteBuilder MapPqcApi(this IEndpointRouteBuilder v1)
    {
        var group = v1.MapGroup("/pqc-exceptions").WithTags("Pqc").RequireAuthorization("admin-role");

        group.MapGet("/", async ([FromQuery] bool? includeInactive, IPqcExceptionService service, CancellationToken ct) =>
            Results.Ok(await service.ListAsync(includeInactive == true, ct)));

        group.MapPost("/", async (CreatePqcExceptionRequest request, IValidator<CreatePqcExceptionRequest> validator,
            IPqcExceptionService service, HttpContext http, IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            var validation = await validator.ValidateAsync(request, ct);
            if (!validation.IsValid) return Results.ValidationProblem(validation.ToErrorDictionary());
            var created = await service.CreateAsync(request, claims.GetName(http.User), claims.GetSubject(http.User), ct);
            return Results.Created($"/v1/pqc-exceptions/{created.Id}", created);
        });

        group.MapPost("/{id:guid}/revoke", async (Guid id, IPqcExceptionService service, HttpContext http,
            IIdentityClaimsMapper claims, CancellationToken ct) =>
        {
            try
            {
                var revoked = await service.RevokeAsync(new PqcExceptionId(id), claims.GetName(http.User), ct);
                return revoked is null ? ApiProblem.NotFound() : Results.Ok(revoked);
            }
            catch (PqcExceptionAlreadyRevokedException ex)
            {
                return ApiProblem.Conflict(ex.Message);
            }
        });

        return v1;
    }

    /// <summary>Maps <c>GET /pqc/migration-report</c> under the <c>/v1</c> group. Read-only; needs certificates.view.</summary>
    public static IEndpointRouteBuilder MapPqcReportApi(this IEndpointRouteBuilder v1)
    {
        // The route grants certificates.view. The observed block is guarded by settings.edit, which the
        // permission policies only evaluate with HttpContext as the resource, so it is resolved here
        // (the same pattern as the dashboard attention route) and handed to the service.
        v1.MapGet("/pqc/migration-report", async (
            [FromQuery] string? template, [FromQuery] string? proposedStage,
            [FromQuery] int? observedDays, [FromQuery] int? page, [FromQuery] int? pageSize,
            IPqcMigrationReportService service, IAuthorizationService authorization,
            HttpContext http, CancellationToken ct) =>
        {
            PqcStage? proposed = null;
            if (!string.IsNullOrWhiteSpace(proposedStage))
            {
                var text = proposedStage.Trim();
                // Enum.TryParse would accept "3"; a stage is named, never numbered.
                if (char.IsDigit(text[0]) || !Enum.TryParse<PqcStage>(text, ignoreCase: true, out var parsed) || !Enum.IsDefined(parsed))
                    return ApiProblem.BadRequest($"proposedStage must be one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");
                proposed = parsed;
            }

            var query = new PqcReportQuery
            {
                TemplateTypeKey = string.IsNullOrWhiteSpace(template) ? null : template.Trim(),
                ProposedStage = proposed,
                ObservedDays = observedDays ?? 30,
                Page = page ?? 1,
                PageSize = pageSize ?? 50
            };
            if (query.Validate() is { } invalid) return ApiProblem.BadRequest(invalid);

            var access = new PqcReportAccess(
                (await authorization.AuthorizeAsync(http.User, http, AppPermissions.SettingsEdit)).Succeeded);
            return Results.Ok(await service.BuildAsync(query, access, ct));
        }).WithTags("Pqc").RequireAuthorization(AppPermissions.CertificatesView).RequireRateLimiting("api");

        return v1;
    }
}
