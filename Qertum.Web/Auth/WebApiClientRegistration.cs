using Qertum.Services;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace Qertum.Web.Auth;

/// <summary>Registers the Web app's typed API client with caller-scoped credentials.</summary>
public static class WebApiClientRegistration
{
    /// <summary>Name of the pooled API transport that carries no user credentials.</summary>
    public const string ClientName = "qertum-api";

    /// <summary>Adds the typed API client with the configured or discovered base address.</summary>
    public static IHttpClientBuilder AddQertumWebApiClient(this IServiceCollection services)
    {
        services.AddTransient<AccessTokenHandler>();
        var builder = services.AddHttpClient(ClientName, (serviceProvider, client) =>
        {
            client.BaseAddress = ResolveApiBaseUrl(serviceProvider.GetRequiredService<IConfiguration>());
        });

        services.AddTransient(serviceProvider =>
        {
            var outer = serviceProvider.GetRequiredService<AccessTokenHandler>();
            outer.InnerHandler = serviceProvider.GetRequiredService<IHttpMessageHandlerFactory>()
                .CreateHandler(ClientName);
            var client = new HttpClient(outer, disposeHandler: false);
            var options = serviceProvider.GetRequiredService<IOptionsMonitor<HttpClientFactoryOptions>>()
                .Get(ClientName);
            foreach (var configure in options.HttpClientActions)
                configure(client);

            return new CertificateRequestsApiClient(client);
        });
        return builder;
    }

    internal static Uri ResolveApiBaseUrl(IConfiguration configuration)
    {
        var hasServiceDiscoveryEndpoint =
            !string.IsNullOrWhiteSpace(configuration["Services:apiservice:https:0"]) ||
            !string.IsNullOrWhiteSpace(configuration["Services:apiservice:http:0"]);

        var baseUrl = hasServiceDiscoveryEndpoint
            ? "https+http://apiservice/"
            : configuration["ApiService:BaseUrl"]?.TrimEnd('/') + "/";

        return new Uri(string.IsNullOrWhiteSpace(baseUrl) ? "https+http://apiservice/" : baseUrl);
    }
}
