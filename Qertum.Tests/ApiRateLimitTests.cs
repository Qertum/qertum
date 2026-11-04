using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;

namespace Qertum.Tests;

public sealed class ApiRateLimitTests
{
    [Theory]
    [InlineData("/ocsp", "/v1/ocsp/AQ%3D%3D")]
    [InlineData("/v1/ocsp", "/ocsp/AQ%3D%3D")]
    public async Task AnonymousOcspRequests_ShareALimitAcrossGetPostAndBothAliases(string postPath, string getPath)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var parent = ApiServiceTests.CreateFactory();
        await using var factory = parent.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:PermitLimit", "2");
            builder.UseSetting("RateLimiting:QueueLimit", "0");
        });
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var client = factory.CreateClient();
        using var body = new ByteArrayContent([1]);
        using var first = await client.PostAsync(postPath, body, ct);
        using var second = await client.GetAsync(getPath, ct);
        using var refused = await client.GetAsync(getPath, ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
    }

    [Fact]
    public async Task OneCallerAtTheLimit_DoesNotLockOutAnother()
    {
        // The limit is per caller, as the REST API documentation says. A single window for everyone let
        // one signed-in client, however low its permissions, refuse the API to every other user.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:PermitLimit", "2");
            builder.UseSetting("RateLimiting:QueueLimit", "0");
        });
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var first = factory.CreateClient();
        first.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Sub", "caller-a");
        var second = factory.CreateClient();
        second.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Sub", "caller-b");

        var answers = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
            answers.Add((await first.GetAsync("/v1/certificate-requests", ct)).StatusCode);
        var other = await second.GetAsync("/v1/certificate-requests", ct);

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], answers);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }
}
