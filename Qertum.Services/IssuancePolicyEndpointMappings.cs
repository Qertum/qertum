using FluentValidation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Auth;
using Qertum.Services.Policies;

namespace Qertum.Services;

public static class IssuancePolicyEndpointMappings
{
    public static RouteGroupBuilder MapIssuancePolicyApi(this RouteGroupBuilder v1)
    {
        var policies = v1.MapGroup("/issuance-policies");

        // Reads use certificates.view so a requester whose request was rejected can see the rule.
        policies.MapGet("/", async (IIssuancePolicyManagementService service, CancellationToken cancellationToken) =>
                Results.Ok(await service.ListAsync(cancellationToken)))
            .RequireAuthorization(AppPermissions.CertificatesView);

        policies.MapGet("/{id:guid}", async (Guid id, IIssuancePolicyManagementService service, CancellationToken cancellationToken) =>
        {
            var policy = await service.GetAsync(id, cancellationToken);
            return policy is null ? ApiProblem.NotFound() : Results.Ok(policy);
        }).RequireAuthorization(AppPermissions.CertificatesView);

        policies.MapGet("/{id:guid}/versions", async (Guid id, IIssuancePolicyManagementService service, CancellationToken cancellationToken) =>
        {
            var versions = await service.GetVersionsAsync(id, cancellationToken);
            return versions is null ? ApiProblem.NotFound() : Results.Ok(versions);
        }).RequireAuthorization(AppPermissions.CertificatesView);

        policies.MapPost("/", async (
            SaveIssuancePolicyRequest request,
            IValidator<SaveIssuancePolicyRequest> validator,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var created = await service.CreateAsync(request, claimsMapper.GetName(httpContext.User), cancellationToken);
            return Results.Created($"/v1/issuance-policies/{created.Id}", created);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapPut("/{id:guid}", async (
            Guid id,
            SaveIssuancePolicyRequest request,
            IValidator<SaveIssuancePolicyRequest> validator,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var updated = await service.UpdateAsync(id, request, claimsMapper.GetName(httpContext.User), cancellationToken);
            return updated is null ? ApiProblem.NotFound() : Results.Ok(updated);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapPut("/{id:guid}/draft", async (
            Guid id,
            SaveIssuancePolicyDraftRequest request,
            IValidator<SaveIssuancePolicyDraftRequest> validator,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var validation = await validator.ValidateAsync(request, cancellationToken);
            if (!validation.IsValid)
                return Results.ValidationProblem(validation.ToErrorDictionary());

            var saved = await service.SaveDraftAsync(id, request, claimsMapper.GetName(httpContext.User), cancellationToken);
            return saved is null ? ApiProblem.NotFound() : Results.Ok(saved);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapDelete("/{id:guid}/draft", async (
            Guid id,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var discarded = await service.DiscardDraftAsync(id, claimsMapper.GetName(httpContext.User), cancellationToken);
            return discarded ? Results.NoContent() : ApiProblem.NotFound();
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapPost("/{id:guid}/publish", async (
            Guid id,
            PublishIssuancePolicyRequest request,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var published = await service.PublishAsync(id, request, claimsMapper.GetName(httpContext.User), cancellationToken);
            return published is null ? ApiProblem.NotFound() : Results.Ok(published);
        }).RequireAuthorization(AppPermissions.PoliciesPublish);

        policies.MapPost("/{id:guid}/archive", async (
            Guid id,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var result = await service.SetArchivedAsync(id, true, claimsMapper.GetName(httpContext.User), cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Ok(result);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapPost("/{id:guid}/unarchive", async (
            Guid id,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var result = await service.SetArchivedAsync(id, false, claimsMapper.GetName(httpContext.User), cancellationToken);
            return result is null ? ApiProblem.NotFound() : Results.Ok(result);
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        policies.MapDelete("/{id:guid}", async (
            Guid id,
            IIssuancePolicyManagementService service,
            HttpContext httpContext, IIdentityClaimsMapper claimsMapper,
            CancellationToken cancellationToken) =>
        {
            var deleted = await service.DeleteAsync(id, claimsMapper.GetName(httpContext.User), cancellationToken);
            return deleted ? Results.NoContent() : ApiProblem.NotFound();
        }).RequireAuthorization(AppPermissions.SettingsEdit);

        return v1;
    }
}
