using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookDestinationConnectionTests
{
    [Fact]
    public async Task HostedWorkerUsesTheCheckedHttpClient()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8")]);
        var connector = new RecordingConnector();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSingleton<IWebhookDnsResolver>(resolver);
        services.AddSingleton<IWebhookSocketConnector>(connector);
        services.AddWebhookDeliveryService();
        using var provider = services.BuildServiceProvider();
        var worker = Assert.Single(provider.GetServices<IHostedService>().OfType<WebhookDeliveryService>());
        var clientField = typeof(WebhookDeliveryService).GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
            .Single(field => field.FieldType == typeof(HttpClient));
        var client = Assert.IsType<HttpClient>(clientField.GetValue(worker));

        using var response = await SendAsync(client, "http://hook.invalid/receive", PublicPolicy());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(resolver.Hosts);
        Assert.Single(connector.Endpoints);
    }

    [Fact]
    public async Task ConnectsToTheIpThatPassedTheDnsPolicyCheck()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8")]);
        var connector = new RecordingConnector();
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        using var response = await SendAsync(client, "http://hook.invalid/receive", PublicPolicy());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("8.8.8.8", Assert.Single(connector.Endpoints).Address.ToString());
        Assert.Equal(80, connector.Endpoints[0].Port);
        Assert.Equal("hook.invalid", Assert.Single(resolver.Hosts));
        Assert.Contains("Host: hook.invalid", Assert.Single(connector.Requests), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MixedDnsAnswerCannotConnect()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8"), IPAddress.Loopback]);
        var connector = new RecordingConnector();
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SendAsync(client, "http://hook.invalid/receive", PublicPolicy()));

        Assert.Empty(connector.Endpoints);
    }

    [Fact]
    public async Task ChangedDnsAnswerIsCheckedOnTheNextConnection()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8")]);
        var connector = new RecordingConnector();
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        using var first = await SendAsync(client, "http://hook.invalid/receive", PublicPolicy());
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        resolver.Answers = [IPAddress.Loopback];

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SendAsync(client, "http://hook.invalid/receive", PublicPolicy()));

        Assert.Equal(2, resolver.Hosts.Count);
        Assert.Single(connector.Endpoints);
    }

    [Fact]
    public async Task EmptyOrFailedDnsNeverConnects()
    {
        var resolver = new RecordingResolver([]);
        var connector = new RecordingConnector();
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SendAsync(client, "http://hook.invalid/receive", PublicPolicy()));
        resolver.Failure = new SocketException((int)SocketError.HostNotFound);
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            SendAsync(client, "http://hook.invalid/receive", PublicPolicy()));

        Assert.Empty(connector.Endpoints);
    }

    [Fact]
    public async Task RedirectIsReturnedWithoutFollowingIt()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8")]);
        var connector = new RecordingConnector(HttpStatusCode.Found);
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        using var response = await SendAsync(client, "http://hook.invalid/receive", PublicPolicy());

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Single(connector.Endpoints);
        Assert.Single(resolver.Hosts);
    }

    [Fact]
    public async Task RequestWithoutPolicySnapshotCannotConnect()
    {
        var resolver = new RecordingResolver([IPAddress.Parse("8.8.8.8")]);
        var connector = new RecordingConnector();
        using var handler = WebhookDestinationHttpHandler.Create(resolver, connector);
        using var client = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(
            "http://hook.invalid/receive", TestContext.Current.CancellationToken));

        Assert.Empty(resolver.Hosts);
        Assert.Empty(connector.Endpoints);
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, string url, WebhookDestinationPolicySnapshot policy)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Options.Set(WebhookDestinationHttpHandler.PolicyKey, policy);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static WebhookDestinationPolicySnapshot PublicPolicy()
        => new(true, WebhookPublicMode.AnyPublic, []);

    private sealed class RecordingResolver(IPAddress[] answers) : IWebhookDnsResolver
    {
        public IPAddress[] Answers { get; set; } = answers;
        public Exception? Failure { get; set; }
        public List<string> Hosts { get; } = [];

        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            Hosts.Add(host);
            if (Failure is not null) throw Failure;
            return Task.FromResult(Answers);
        }
    }

    private sealed class RecordingConnector(HttpStatusCode status = HttpStatusCode.OK) : IWebhookSocketConnector
    {
        public List<IPEndPoint> Endpoints { get; } = [];
        public List<string> Requests { get; } = [];

        public ValueTask<Stream> ConnectAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            Endpoints.Add(endpoint);
            return ValueTask.FromResult<Stream>(new ScriptedHttpStream(status, request => Requests.Add(request)));
        }
    }

    private sealed class ScriptedHttpStream(HttpStatusCode status, Action<string> record) : Stream
    {
        private readonly MemoryStream _response = new(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {(int)status} {status}\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"));
        private readonly MemoryStream _request = new();

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => _response.Read(buffer, offset, count);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _response.ReadAsync(buffer, cancellationToken);
        public override void Write(byte[] buffer, int offset, int count) => _request.Write(buffer, offset, count);
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _request.WriteAsync(buffer, cancellationToken);
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                record(Encoding.ASCII.GetString(_request.ToArray()));
                _response.Dispose();
                _request.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
