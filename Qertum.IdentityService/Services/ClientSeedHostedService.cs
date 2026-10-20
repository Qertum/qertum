using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Stores;
using OpenIddict.Abstractions;

namespace Qertum.IdentityService.Services;

public sealed class ClientSeedHostedService(
    IServiceProvider services,
    JsonClientStore clientStore,
    IConfiguration configuration,
    IdentityServiceOptions options,
    ILogger<ClientSeedHostedService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        // Under Aspire the web frontend's URL is only known at runtime, so its redirect URIs
        // are injected from service discovery. Standalone deployments normally have no such
        // variables and must treat clients.json as the sole source of redirect URIs, so this
        // is off by default outside Development; a deployment that injects the variables
        // itself (deploy/single-container) opts back in explicitly.
        var webFrontendBaseUrls = new List<string>();
        if (options.ServiceDiscoveryRedirectUrisEnabled)
        {
            foreach (var scheme in new[] { "https", "http" })
            {
                // Aspire injects Services__webfrontend__https__0 / Services__webfrontend__http__0
                var url = configuration[$"Services:webfrontend:{scheme}:0"];
                if (!string.IsNullOrWhiteSpace(url))
                    webFrontendBaseUrls.Add(url.TrimEnd('/'));
            }
        }

        var configuredApiSecret = options.ApiClientSecret;

        foreach (var client in clientStore.GetAll())
        {
            var existing = await manager.FindByClientIdAsync(client.ClientId, cancellationToken);

            var effectiveSecret = (client.ClientId == "qertum-api" && !string.IsNullOrWhiteSpace(configuredApiSecret))
                ? configuredApiSecret
                : client.ClientSecret;

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = client.ClientId,
                ClientSecret = effectiveSecret,
                DisplayName = client.DisplayName,
                ClientType = client.ClientType,
                ConsentType = client.ConsentType
            };

            foreach (var uri in client.RedirectUris)
                descriptor.RedirectUris.Add(new Uri(uri));

            foreach (var uri in client.PostLogoutRedirectUris)
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));

            foreach (var permission in client.Permissions)
                descriptor.Permissions.Add(permission);

            // Inject Aspire-discovered web frontend redirect URIs so tests and local dev runs
            // don't require hardcoded port numbers in clients.json.
            if (client.ClientId == "qertum-web")
            {
                foreach (var baseUrl in webFrontendBaseUrls)
                {
                    descriptor.RedirectUris.Add(new Uri($"{baseUrl}/signin-oidc"));
                    descriptor.PostLogoutRedirectUris.Add(new Uri($"{baseUrl}/signout-callback-oidc"));
                }
            }

            if (existing is null)
            {
                await manager.CreateAsync(descriptor, cancellationToken);
                logger.LogInformation("Registered OpenIddict client {ClientId}", client.ClientId);
            }
            else
            {
                await manager.UpdateAsync(existing, descriptor, cancellationToken);
                logger.LogInformation("Updated OpenIddict client {ClientId}", client.ClientId);
            }
        }

        await RemoveStaleTestClientsAsync(manager, cancellationToken);
    }

    /// <summary>
    /// Deletes the integration-test clients from the OpenIddict store unless they are explicitly
    /// wanted. Removing them from clients.json is not enough on its own: the loop above does
    /// create-or-update and never prunes, so an application row seeded by an earlier version
    /// keeps working — including qertum-test-m2m, which is an admin whose secret is published in
    /// this repository.
    /// </summary>
    private async Task RemoveStaleTestClientsAsync(
        IOpenIddictApplicationManager manager, CancellationToken cancellationToken)
    {
        if (options.SeedTestClients) return;

        foreach (var clientId in JsonClientStore.TestClientIds)
        {
            var application = await manager.FindByClientIdAsync(clientId, cancellationToken);
            if (application is null) continue;

            await manager.DeleteAsync(application, cancellationToken);
            logger.LogWarning(
                "Deleted integration-test client {ClientId} from the OpenIddict store. It carries a " +
                "secret published in the source and must not exist outside the test harness.",
                clientId);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
