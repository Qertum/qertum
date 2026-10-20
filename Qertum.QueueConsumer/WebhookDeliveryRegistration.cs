using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Qertum.QueueConsumer;

internal static class WebhookDeliveryRegistration
{
    internal static IServiceCollection AddWebhookDeliveryService(this IServiceCollection services)
    {
        services.TryAddSingleton<IWebhookDnsResolver, SystemWebhookDnsResolver>();
        services.TryAddSingleton<IWebhookSocketConnector, SocketWebhookConnector>();
        services.AddHttpClient<WebhookDeliveryService>()
            .ConfigurePrimaryHttpMessageHandler(sp => WebhookDestinationHttpHandler.Create(
                sp.GetRequiredService<IWebhookDnsResolver>(), sp.GetRequiredService<IWebhookSocketConnector>()));
        services.AddHostedService(sp => sp.GetRequiredService<WebhookDeliveryService>());
        return services;
    }
}
