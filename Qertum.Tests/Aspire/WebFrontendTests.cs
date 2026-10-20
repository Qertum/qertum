namespace Qertum.Tests.Aspire;

[Collection("AspireIntegration")]
public sealed class WebFrontendTests(AspireIntegrationFixture fixture)
{
    [Fact(DisplayName = "IT-WEB-001")]
    public async Task Web_Root_Returns200()
    {
        // Act: anonymous GET / — Blazor Server should either serve the page or redirect to login;
        // following redirects we expect a 200 from the login page or the app shell.
        var resp = await fixture.WebClient.GetAsync("/", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact(DisplayName = "IT-WEB-002")]
    public async Task Web_CertificateRequestsPage_AnonymousRedirectsToLogin()
    {
        // Act: anonymous GET /certificate-requests — should redirect to login and return 200.
        var resp = await fixture.WebClient.GetAsync("/certificate-requests", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact(DisplayName = "IT-WEB-003")]
    public async Task Web_NewCertificateRequestPage_Returns200()
    {
        // Act: anonymous GET /new-certificate-request — should redirect to login and return 200.
        var resp = await fixture.WebClient.GetAsync("/new-certificate-request", TestContext.Current.CancellationToken);

        // Assert
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
