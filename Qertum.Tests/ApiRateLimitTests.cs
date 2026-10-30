using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;

namespace Qertum.Tests;

public sealed class ApiRateLimitTests
{
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
