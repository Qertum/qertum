using System.Net;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Qertum.Services.Acme;

public static class AcmeServiceCollectionExtensions
{
    public static IServiceCollection AddAcmeServices(this IServiceCollection services)
    {
        // Only a fallback. The host registers Redis first (AddQertumDistributedCache), including
        // the connection multiplexer used to consume nonces atomically across instances.
        if (services.All(d => d.ServiceType != typeof(Microsoft.Extensions.Caching.Distributed.IDistributedCache)))
            services.AddDistributedMemoryCache();
        services.AddOptions<AcmeDns01Options>()
            .BindConfiguration(AcmeDns01Options.SectionName);
        services.AddSingleton<IAcmeDnsResolver, DnsClientAcmeDnsResolver>();

        services.TryAddSingleton<ProtocolMetrics>();
        services.AddSingleton<IAcmeNonceService, AcmeNonceService>();
        services.AddScoped<JwsRequestParser>();
        services.AddSingleton<IAcmeChallengeVerifier, AcmeChallengeVerifier>();
        services.AddSingleton<IAcmeAddressPolicy, AcmeAddressPolicy>();

        services.AddHttpClient("acme-challenge", client =>
            {
                // Without this the default 100-second timeout applies, so one unresponsive challenge
                // target occupies the verification loop for over a minute.
                client.Timeout = TimeSpan.FromSeconds(10);

                // A key authorization is a token plus a base64url SHA-256 thumbprint — well under 128
                // bytes. Capping the buffer turns a target that streams gigabytes into a fast,
                // contained failure instead of an out-of-memory kill.
                client.MaxResponseContentBufferSize = 1024;
            })
            .ConfigurePrimaryHttpMessageHandler(provider => BuildGuardedHandler(provider))
            .SetHandlerLifetime(TimeSpan.FromMinutes(5));

        return services;
    }

    /// <summary>
    /// Builds the handler that enforces the ACME address policy.
    /// </summary>
    /// <remarks>
    /// The policy runs inside <see cref="SocketsHttpHandler.ConnectCallback"/> rather than before the
    /// request. Resolving in the caller and then handing a hostname to HttpClient leaves a gap: the
    /// handler performs its own lookup, so a DNS record that changes between the two resolutions
    /// connects to an address nobody checked — classic DNS rebinding. Resolving inside the callback
    /// means the address validated is the exact address the socket connects to.
    /// </remarks>
    private static SocketsHttpHandler BuildGuardedHandler(IServiceProvider provider)
    {
        var handler = new SocketsHttpHandler
        {
            // Load-bearing, not an arbitrary default: a 302 to http://169.254.169.254/ would
            // otherwise bypass the address policy entirely, since redirects are followed by the
            // handler without re-entering any of our checks.
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(5)
        };

        handler.ConnectCallback = async (context, cancellationToken) =>
        {
            var policy = provider.GetRequiredService<IAcmeAddressPolicy>();
            var host = context.DnsEndPoint.Host;

            var allowedNetworksJson = await ReadAllowedNetworksAsync(provider, cancellationToken);

            IPAddress[] addresses;
            if (IPAddress.TryParse(host, out var literal))
            {
                addresses = [literal];
            }
            else
            {
                try
                {
                    addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
                }
                catch (SocketException ex)
                {
                    throw new AcmeAddressDeniedException($"Could not resolve host '{host}': {ex.Message}");
                }
            }

            if (addresses.Length == 0)
                throw new AcmeAddressDeniedException($"Host '{host}' did not resolve to any address.");

            // Every resolved address must pass, not merely one: the handler chooses which address to
            // use, so a name resolving to both a permitted host and 169.254.169.254 must be rejected.
            foreach (var address in addresses)
            {
                var decision = policy.Evaluate(address, host, allowedNetworksJson);
                if (!decision.Allowed)
                    throw new AcmeAddressDeniedException(decision.DenyReason!);
            }

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                // Connect to the addresses just validated, never to the hostname again.
                await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

        return handler;
    }

    private static async Task<string?> ReadAllowedNetworksAsync(IServiceProvider provider, CancellationToken cancellationToken)
    {
        // A scope per connect: the allowlist is operator-editable and must take effect without a
        // restart. Challenge verification is low-volume, so the extra read is not worth caching.
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();

        return await db.Settings
            .Where(s => s.Id == 1)
            .Select(s => s.AcmeChallengeAllowedNetworksJson)
            .FirstOrDefaultAsync(cancellationToken);
    }
}
