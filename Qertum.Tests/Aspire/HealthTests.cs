namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class HealthTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-HEALTH-001")]
    public async Task ApiService_Health_Returns200()
    {
        var response = await fixture.ApiClientAnon.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "IT-HEALTH-002")]
    public async Task IdentityService_Health_Returns200()
    {
        using var client = fixture.App.CreateHttpClient("identityservice", "https");
        var response = await client.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact(DisplayName = "IT-HEALTH-003")]
    public async Task WebFrontend_Health_Returns200()
    {
        var response = await fixture.WebClient.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
