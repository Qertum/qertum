using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Qertum.Tests.IdpInterop;

public sealed class MockOidcLifetime : IAsyncLifetime
{
    public MockOidcFixture? Idp { get; private set; }
    public WebApplicationFactory<ApiServiceProgram>? Api { get; private set; }
    public string? Unavailable { get; private set; }

    public async ValueTask InitializeAsync()
    {
        if (!await DockerContainer.IsAvailableAsync())
        {
            Unavailable = "Docker is not available.";
            return;
        }

        Idp = await MockOidcFixture.StartAsync(CancellationToken.None);
        // 1800 s: the "fresh" token must stay fresh however long the class takes; "stale" is 7200 s old.
        Api = await IdpApiHost.CreateAsync(Idp.Authority, maxAgeSeconds: 1800, CancellationToken.None);
    }

    public async ValueTask DisposeAsync()
    {
        if (Api is not null) await Api.DisposeAsync();
        if (Idp is not null) await Idp.DisposeAsync();
    }
}

/// <summary>The claims contract against a second, independent OIDC implementation: real token validation, chosen claim shapes.</summary>
public sealed class MockOidcContractTests(MockOidcLifetime lifetime) : IClassFixture<MockOidcLifetime>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private async Task<HttpResponseMessage> RenameAsync(string scenario)
    {
        Assert.SkipWhen(lifetime.Idp is null, lifetime.Unavailable ?? "Docker is not available.");
        var token = await lifetime.Idp!.TokenAsync(scenario, Ct);
        var client = lifetime.Api!.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.PostAsync("/v1/permissions/ghost/rename",
            new StringContent("""{"newRole":"renamed"}""", Encoding.UTF8, "application/json"), Ct);
    }

    [Theory]
    [InlineData("fresh")]
    [InlineData("multiacr")]
    [InlineData("stringtime")]
    public async Task AcceptableTokens_ReachTheHandler(string scenario)
    {
        var response = await RenameAsync(scenario);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("stale", "too old")]
    [InlineData("future", "in the future")]
    [InlineData("wrongacr", "not one this server accepts")]
    [InlineData("uppercaseacr", "not one this server accepts")]
    [InlineData("noacr", "no authentication class")]
    [InlineData("noauthtime", "no authentication time")]
    [InlineData("floattime", "not a valid Unix timestamp")]
    public async Task UnacceptableTokens_AreChallenged_WithTheReason(string scenario, string reason)
    {
        var response = await RenameAsync(scenario);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("insufficient_user_authentication", string.Join(' ', response.Headers.GetValues("WWW-Authenticate")));
        Assert.Contains(reason, await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task AnUnprotectedRoute_AcceptsAnyOfThem_ThatIsOtherwiseValid()
    {
        Assert.SkipWhen(lifetime.Idp is null, lifetime.Unavailable ?? "Docker is not available.");
        var client = lifetime.Api!.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await lifetime.Idp!.TokenAsync("noacr", Ct));

        var response = await client.GetAsync("/v1/issuers", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
