using System.Net;
using System.Text;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class ApiClientCorrelationIdTests
{
    private sealed class Stub(HttpStatusCode status, string? correlationId) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(status)
            {
                Content = new StringContent("""{"title":"Internal Server Error","detail":"boom"}""", Encoding.UTF8, "application/problem+json")
            };
            if (correlationId is not null)
                response.Headers.Add("X-Correlation-Id", correlationId);
            return Task.FromResult(response);
        }
    }

    private static CertificateRequestsApiClient Client(HttpStatusCode status, string? correlationId) =>
        new(new HttpClient(new Stub(status, correlationId)) { BaseAddress = new Uri("http://api.test/") });

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task AFailedCall_ExposesTheCorrelationIdFromTheResponseHeader(HttpStatusCode status)
    {
        var ct = TestContext.Current.CancellationToken;

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => Client(status, "4bf92f3577b34da6a3ce929d0e0e4736").GetAttentionAsync(ct));

        Assert.Equal("4bf92f3577b34da6a3ce929d0e0e4736", ex.CorrelationId);
        Assert.Equal(status, ex.StatusCode);
    }

    [Fact]
    public async Task AFailedCallWithoutTheHeader_HasNoCorrelationId_NotAGuess()
    {
        var ct = TestContext.Current.CancellationToken;

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => Client(HttpStatusCode.InternalServerError, null).GetAttentionAsync(ct));

        Assert.Null(ex.CorrelationId);
    }

    [Fact]
    public async Task TheMessageStaysTheDetail_TheIdIsNotMixedIntoIt()
    {
        var ct = TestContext.Current.CancellationToken;

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => Client(HttpStatusCode.InternalServerError, "abc").GetAttentionAsync(ct));

        Assert.Equal("boom", ex.Message);
    }
}
