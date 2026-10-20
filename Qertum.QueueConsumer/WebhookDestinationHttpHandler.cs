using System.Net;
using System.Net.Sockets;
using Qertum.Services.Webhooks;

namespace Qertum.QueueConsumer;

internal interface IWebhookDnsResolver
{
    Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken);
}

internal sealed class SystemWebhookDnsResolver : IWebhookDnsResolver
{
    public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        => Dns.GetHostAddressesAsync(host, cancellationToken);
}

internal interface IWebhookSocketConnector
{
    ValueTask<Stream> ConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken);
}

internal sealed class SocketWebhookConnector : IWebhookSocketConnector
{
    public async ValueTask<Stream> ConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(endpoint, cancellationToken);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

internal static class WebhookDestinationHttpHandler
{
    internal static readonly HttpRequestOptionsKey<WebhookDestinationPolicySnapshot> PolicyKey =
        new("WebhookDestinationPolicy");

    internal static SocketsHttpHandler Create(IWebhookDnsResolver resolver, IWebhookSocketConnector connector)
        => new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.Zero,
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (!context.InitialRequestMessage.Options.TryGetValue(PolicyKey, out var policy) ||
                    !WebhookDestinationTarget.TryParse(context.InitialRequestMessage.RequestUri?.OriginalString,
                        out var target, out _))
                    throw new HttpRequestException("Webhook destination policy is unavailable.");

                IPAddress[] addresses;
                if (IPAddress.TryParse(target!.Host, out var literal))
                    addresses = [literal];
                else
                {
                    try
                    {
                        addresses = await resolver.ResolveAsync(target.Host, cancellationToken);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        throw new HttpRequestException("Webhook destination DNS resolution failed.", ex);
                    }
                }

                var decision = WebhookAddressPolicy.Check(policy, target, addresses);
                if (!decision.Allowed)
                    throw new HttpRequestException(decision.Reason);

                return await connector.ConnectAsync(new IPEndPoint(addresses[0], target.Port), cancellationToken);
            }
        };
}
