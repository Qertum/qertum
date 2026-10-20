using System.Net;
using System.Text;
using Qertum.Services;

namespace Qertum.Tests.Engineering;

/// <summary>
/// The API may sit behind a reverse proxy under a path prefix (https://host/qertum-api/). The typed
/// client's paths are relative, so the prefix in its base address survives; an absolute "/v1/…" path
/// would silently drop it. The CLI relies on this since it calls the API through this client.
/// </summary>
public sealed class ApiClientBaseAddressTests
{
    [Fact]
    public async Task APathPrefixInTheBaseAddressIsKept()
    {
        var handler = new RecordingHandler();
        var client = new CertificateRequestsApiClient(
            new HttpClient(handler) { BaseAddress = new Uri("https://host.example/qertum-api/") });

        await client.GetCaStatusAsync(TestContext.Current.CancellationToken);

        Assert.Equal("/qertum-api/v1/ca/status", handler.LastPath);
    }

    [Fact]
    public void NoClientPathIsAbsolute()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(root.FullName, "Qertum.sln"))) root = root.Parent!;
        var source = File.ReadAllText(Path.Combine(root.FullName, "Qertum.ApiClient", "CertificateRequestsApiClient.cs"));

        Assert.DoesNotContain("\"/v1/", source, StringComparison.Ordinal);
        Assert.DoesNotContain("\"/ca/", source, StringComparison.Ordinal);
        Assert.DoesNotContain("\"/audit-log", source, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFailedReadCarriesTheServersDetail()
    {
        // Reads used GetFromJsonAsync, whose HttpRequestException has no body; the CLI would then
        // print "Response status code does not indicate success" instead of the reason.
        var client = new CertificateRequestsApiClient(new HttpClient(new ProblemHandler())
        {
            BaseAddress = new Uri("https://host.example/")
        });

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetSettingsAsync(TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Equal("Needs settings.edit.", ex.Detail);
    }

    private sealed class ProblemHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
            {
                Content = new StringContent("""{"title":"Forbidden","status":403,"detail":"Needs settings.edit."}""",
                    Encoding.UTF8, "application/problem+json")
            });
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public string? LastPath { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastPath = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json")
            });
        }
    }
}
