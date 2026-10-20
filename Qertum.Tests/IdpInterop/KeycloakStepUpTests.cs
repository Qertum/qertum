using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;

namespace Qertum.Tests.IdpInterop;

public sealed class KeycloakLifetime : IAsyncLifetime
{
    public KeycloakFixture? Idp { get; private set; }
    public WebApplicationFactory<ApiServiceProgram>? Api { get; private set; }
    public string? Unavailable { get; private set; }

    public async ValueTask InitializeAsync()
    {
        if (!await DockerContainer.IsAvailableAsync())
        {
            Unavailable = "Docker is not available.";
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        Idp = await KeycloakFixture.StartAsync(cts.Token);
        // 20 s: long enough for a login and a call, short enough to watch a token go stale in the test below.
        Api = await IdpApiHost.CreateAsync(Idp.Authority, maxAgeSeconds: 20, cts.Token);
    }

    public async ValueTask DisposeAsync()
    {
        if (Api is not null) await Api.DisposeAsync();
        if (Idp is not null) await Idp.DisposeAsync();
    }
}

/// <summary>
/// Qertum's step-up against a real Keycloak: a realm whose level-of-assurance flow turns "password and one-time code" into
/// <c>acr: mfa</c>, tokens validated for real (issuer, audience, signature from Keycloak's keys).
/// </summary>
public sealed class KeycloakStepUpTests(KeycloakLifetime lifetime) : IClassFixture<KeycloakLifetime>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private KeycloakFixture Idp
    {
        get
        {
            Assert.SkipWhen(lifetime.Idp is null, lifetime.Unavailable ?? "Docker is not available.");
            return lifetime.Idp!;
        }
    }

    private async Task<HttpResponseMessage> RenameAsync(string token)
    {
        var client = lifetime.Api!.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.PostAsync("/v1/permissions/ghost/rename",
            new StringContent("""{"newRole":"renamed"}""", Encoding.UTF8, "application/json"), Ct);
    }

    [Fact]
    public async Task APasswordOnlyToken_IsChallenged_AndAnMfaLoginGetsThrough()
    {
        var user = await Idp.NewUserAsync(Ct);
        var browser = new KeycloakFixture.Browser();

        var weak = await RenameAsync(await Idp.LoginAsync(user, browser, ct: Ct));
        Assert.Equal(HttpStatusCode.Unauthorized, weak.StatusCode);
        var challenge = string.Join(' ', weak.Headers.GetValues("WWW-Authenticate"));
        Assert.Contains("acr_values=\"mfa\"", challenge);
        Assert.Contains("max_age=\"20\"", challenge);

        // The step-up the Web UI performs: the same browser session, asked for the challenge's acr_values and max_age.
        var strong = await RenameAsync(await Idp.LoginAsync(user, browser, acrValues: "mfa", maxAge: 20, ct: Ct));
        Assert.Equal(HttpStatusCode.NotFound, strong.StatusCode);
    }

    [Fact]
    public async Task AnMfaToken_GoesStale_AndMaxAgeForcesAFreshSignIn()
    {
        var user = await Idp.NewUserAsync(Ct);
        var browser = new KeycloakFixture.Browser();
        var token = await Idp.LoginAsync(user, browser, acrValues: "mfa", ct: Ct);
        var otpWindowUsed = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Assert.Equal(HttpStatusCode.NotFound, (await RenameAsync(token)).StatusCode);

        await Task.Delay(TimeSpan.FromSeconds(22), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, (await RenameAsync(token)).StatusCode);

        // Keycloak accepts a one-time code once per 30 s window, and 22 s does not always cross a window boundary:
        // wait until the clock is in a later window than the login above used.
        while (DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30 <= otpWindowUsed)
            await Task.Delay(TimeSpan.FromMilliseconds(500), Ct);

        // max_age forces re-authentication: the new token's auth_time is recent again.
        var renewed = await RenameAsync(await Idp.LoginAsync(user, browser, acrValues: "mfa", maxAge: 1, ct: Ct));
        Assert.Equal(HttpStatusCode.NotFound, renewed.StatusCode);
    }

    [Fact]
    public async Task TheKeycloakIssuer_IsExactlyTheConfiguredAuthority()
    {
        var user = await Idp.NewUserAsync(Ct);
        var token = await Idp.LoginAsync(user, new KeycloakFixture.Browser(), ct: Ct);

        var payload = token.Split('.')[1];
        payload = payload.Replace('-', '+').Replace('_', '/').PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
        var claims = System.Text.Json.Nodes.JsonNode.Parse(Convert.FromBase64String(payload))!;

        Assert.Equal(Idp.Authority, claims["iss"]!.GetValue<string>());
        Assert.Equal("qertum-api", claims["aud"]!.GetValue<string>());
        Assert.NotNull(claims["auth_time"]);
    }
}
