using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Http.Resilience;
using Qertum.Services;

namespace Qertum.Tests.Engineering;

/// <summary>
/// The approval preview GET is audited on the server, so a retry by the standard resilience handler
/// writes a second <c>ApprovalPreviewed</c> entry for one look. That request opts out of retries;
/// every other request keeps them.
/// </summary>
public sealed class HttpRetryOptOutTests
{
    private const string ClientName = "retry-test";

    [Fact]
    public async Task ApprovalPreview_IsSentOnce_WhenTheServerFails()
    {
        var (client, transport) = NewClient();

        await Assert.ThrowsAsync<ApiProblemException>(() =>
            client.PreviewApprovalAsync(new CertificateRequestId(Guid.NewGuid()), TestContext.Current.CancellationToken));

        Assert.Equal(1, transport.Calls);
    }

    [Fact]
    public async Task OtherRequests_AreStillRetried()
    {
        var (client, transport) = NewClient();

        await Assert.ThrowsAsync<ApiProblemException>(() => client.GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.True(transport.Calls > 1, $"Expected retries, saw {transport.Calls} call(s).");
    }

    [Fact]
    public void ApiClientAndServiceDefaults_UseTheSameOptionName() =>
        Assert.Equal(HttpRetryOptOut.OptionName, ApiRequestOptions.NoRetry);

    private static (CertificateRequestsApiClient Client, CountingTransport Transport) NewClient()
    {
        var transport = new CountingTransport();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Test" });
        builder.AddServiceDefaults();
        builder.Services.AddHttpClient(ClientName).ConfigurePrimaryHttpMessageHandler(() => transport);
        // Keep the retried case fast; the opt-out predicate is what is under test, not the delays.
        builder.Services.Configure<HttpStandardResilienceOptions>($"{ClientName}-standard", o => o.Retry.Delay = TimeSpan.Zero);
        var host = builder.Build();

        var http = host.Services.GetRequiredService<IHttpClientFactory>().CreateClient(ClientName);
        http.BaseAddress = new Uri("http://api.test/");
        return (new CertificateRequestsApiClient(http), transport);
    }

    private sealed class CountingTransport : HttpMessageHandler
    {
        private int _calls;
        public int Calls => _calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        }
    }
}
