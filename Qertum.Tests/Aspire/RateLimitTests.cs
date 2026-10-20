namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class RateLimitTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-RATELIMIT-001")]
    public async Task RateLimit_RequestsWithinWindow_AreAccepted()
    {
        // Act: send 10 rapid requests
        var tasks = Enumerable.Range(0, 10).Select(_ =>
            fixture.ApiClientAsAdmin.GetAsync("/v1/certificate-requests", TestContext.Current.CancellationToken));
        var responses = await Task.WhenAll(tasks);

        // Assert: all 200 OK
        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
    }
}
