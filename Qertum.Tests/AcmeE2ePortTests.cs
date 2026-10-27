using System.Net;

namespace Qertum.Tests;

public sealed class AcmeE2ePortTests
{
    [Theory]
    [InlineData("http://case.localhost/.well-known/acme-challenge/token", 18080)]
    [InlineData("http://localhost/.well-known/acme-challenge/token", 18080)]
    [InlineData("http://example.com/.well-known/acme-challenge/token", 80)]
    [InlineData("http://case.localhost:8080/.well-known/acme-challenge/token", 8080)]
    [InlineData("https://case.localhost/.well-known/acme-challenge/token", 443)]
    public async Task OverrideOnlyChangesDefaultHttpPortForLocalhost(string address, int expectedPort)
    {
        var capture = new CaptureHandler();
        using var handler = new E2eHttp01PortHandler(18080) { InnerHandler = capture };
        using var client = new HttpClient(handler);
        using var response = await client.GetAsync(address, TestContext.Current.CancellationToken);
        Assert.Equal(expectedPort, capture.Port);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        public int Port { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Port = request.RequestUri!.Port;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
