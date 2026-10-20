using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Qertum.Services.Auth;

namespace Qertum.Services.Webhooks;

/// <summary>Admin-only routes for webhook destination policy management.</summary>
public static class WebhookDestinationEndpointMappings
{
    /// <summary>Maps the policy routes under the supplied `/v1` group.</summary>
    public static RouteGroupBuilder MapWebhookDestinationApi(this RouteGroupBuilder v1)
    {
        var group = v1.MapGroup("/webhook-destinations").RequireAuthorization("admin-role");

        group.MapGet("", async (IWebhookDestinationPolicyService service, CancellationToken ct) =>
            Results.Ok(ToResponse(await service.GetEffectiveAsync(ct))));

        group.MapPut("/mode", async (SetWebhookDestinationModeRequest request,
            IWebhookDestinationPolicyService service, HttpContext context,
            IIdentityClaimsMapper claimsMapper, CancellationToken ct) =>
        {
            if (request.PublicMode.HasValue && !Enum.IsDefined(request.PublicMode.Value))
                return Results.BadRequest(new { detail = "Unknown public-destination mode." });
            await service.SetPublicModeAsync(request.PublicMode, claimsMapper.GetName(context.User), ct);
            return Results.Ok(ToResponse(await service.GetEffectiveAsync(ct)));
        });

        group.MapPost("/rules", async (SaveWebhookDestinationRuleRequest request,
            IWebhookDestinationPolicyService service, HttpContext context,
            IIdentityClaimsMapper claimsMapper, CancellationToken ct) =>
        {
            try
            {
                var rule = await service.AddRuleAsync(request, claimsMapper.GetName(context.User), ct);
                return Results.Created($"/v1/webhook-destinations/rules/{rule.Id}", ToResponse(rule));
            }
            catch (ArgumentException ex)
            {
                return Results.BadRequest(new { detail = ex.Message });
            }
            catch (InvalidOperationException ex) when (ex.Message == "Destination rule already exists.")
            {
                return Results.Conflict(new { detail = ex.Message });
            }
        });

        group.MapPut("/rules/{id:guid}/enabled", async (Guid id,
            SetWebhookDestinationRuleEnabledRequest request, IWebhookDestinationPolicyService service,
            HttpContext context, IIdentityClaimsMapper claimsMapper, CancellationToken ct) =>
        {
            var rule = await service.SetRuleEnabledAsync(id, request.Enabled,
                claimsMapper.GetName(context.User), ct);
            return rule is null ? Results.NotFound() : Results.Ok(ToResponse(rule));
        });

        group.MapDelete("/rules/{id:guid}", async (Guid id, IWebhookDestinationPolicyService service,
            HttpContext context, IIdentityClaimsMapper claimsMapper, CancellationToken ct) =>
            await service.DeleteAdminRuleAsync(id, claimsMapper.GetName(context.User), ct) switch
            {
                WebhookDestinationDeleteResult.Deleted => Results.NoContent(),
                WebhookDestinationDeleteResult.NotFound => Results.NotFound(),
                WebhookDestinationDeleteResult.ConfigurationRule => Results.Conflict(new
                {
                    detail = "Configuration rules can be disabled here or removed from JSON configuration."
                }),
                _ => Results.StatusCode(500)
            });

        return v1;
    }

    private static WebhookDestinationPolicyResponse ToResponse(WebhookDestinationPolicySnapshot snapshot)
        => new()
        {
            Initialized = snapshot.Initialized,
            PublicMode = snapshot.PublicMode,
            Rules = snapshot.Rules.Select(ToResponse).ToArray()
        };

    private static WebhookDestinationRuleResponse ToResponse(WebhookDestinationRuleSnapshot rule)
        => new()
        {
            Id = rule.Id, Source = rule.Source, Kind = rule.Kind,
            Scheme = rule.Scheme, Host = rule.Host, Port = rule.Port,
            Enabled = rule.Enabled,
            AllowedIpAddresses = rule.AllowedIpAddresses.Select(ip => ip.ToString()).ToArray()
        };
}
