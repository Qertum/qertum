using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Qertum.Services;

/// <summary>
/// Probes the Identity Service OIDC discovery endpoint to verify it is reachable.
/// Uses a short timeout so a slow or unresponsive IDM is detected quickly.
/// </summary>
public sealed class IdentityServiceHealthCheck(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration) : IHealthCheck
{
    public const string ClientName = "identity-health";

    private static string? Normalize(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        // The configured authority wins: with an external identity provider there is no Aspire service entry to find.
        var authority = Normalize(configuration["Identity:Authority"])
            ?? configuration["Services:identityservice:https:0"]
            ?? configuration["Services:identityservice:http:0"]
            ?? configuration["IdentityService:Authority"]
            ?? "https://localhost:7099";

        var discoveryUrl = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";

        try
        {
            var client = httpClientFactory.CreateClient(ClientName);
            var response = await client.GetAsync(discoveryUrl, cancellationToken);
            return response.IsSuccessStatusCode
                ? HealthCheckResult.Healthy()
                : HealthCheckResult.Degraded($"Identity Service returned {(int)response.StatusCode} from {discoveryUrl}.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy($"Cannot reach Identity Service at {discoveryUrl}.", ex);
        }
    }
}
