using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services.Auth;
using Qertum.Tests.Issuers;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.AspNetCore.Http;

namespace Qertum.Tests.Auth;

public sealed class StepUpEndpointTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static IssuerApiHost Host(bool enabled = true) => new(services =>
    {
        services.RemoveAll<StepUpEvaluator>();
        services.AddSingleton(new StepUpEvaluator(
            new StepUpOptions { Enabled = enabled, AcrValues = "mfa", MaxAgeSeconds = 300 }, new FakeTimeProvider(Now)));
    });

    private static HttpClient Client(IssuerApiHost host, string? acr, DateTimeOffset? authTime)
    {
        var client = host.Factory.CreateClient();
        var parameter = string.Join(' ', new[]
        {
            acr is null ? null : $"acr={acr}",
            authTime is null ? null : $"auth_time={authTime.Value.ToUnixTimeSeconds()}"
        }.Where(p => p is not null));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-StepUp", parameter.Length == 0 ? "none=1" : parameter);
        return client;
    }

    private static string Url(string pattern) => pattern.Replace("{id:guid}", Guid.NewGuid().ToString()).Replace("{role}", "ghost");

    private static HttpRequestMessage Request(string method, string pattern) => new(new HttpMethod(method), Url(pattern))
    {
        Content = method is "GET" or "DELETE" ? null : new StringContent("{}", Encoding.UTF8, "application/json")
    };

    private static HttpRequestMessage Probe() => new(HttpMethod.Post, "/v1/permissions/ghost/rename")
    {
        Content = new StringContent("""{"newRole":"renamed"}""", Encoding.UTF8, "application/json")
    };

    [Fact]
    public async Task AProtectedRoute_WithoutTheClaims_IsChallengedPerRfc9470()
    {
        await using var host = Host();

        var response = await Client(host, acr: null, authTime: null).SendAsync(Probe(), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = string.Join(' ', response.Headers.GetValues("WWW-Authenticate"));
        Assert.StartsWith("Bearer ", challenge);
        Assert.Contains("error=\"insufficient_user_authentication\"", challenge);
        Assert.Contains("acr_values=\"mfa\"", challenge);
        Assert.Contains("max_age=\"300\"", challenge);
        Assert.True(response.Headers.Contains("X-Correlation-Id"));
        var body = await response.Content.ReadAsStringAsync(Ct);
        Assert.Contains("Step-up authentication required", body);
    }

    [Theory]
    [InlineData("pwd", 10)]
    [InlineData("mfa", 301)]
    public async Task WrongAcrOrAStaleLogin_IsChallenged(string acr, int ageSeconds)
    {
        await using var host = Host();

        var response = await Client(host, acr, Now.AddSeconds(-ageSeconds)).SendAsync(Probe(), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AFreshMfaToken_ReachesTheHandler()
    {
        await using var host = Host();

        var response = await Client(host, "mfa", Now.AddSeconds(-5)).SendAsync(Probe(), Ct);

        // The handler answered: an unknown role has no grants to rename.
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task EveryProtectedRoute_IsChallenged_WithoutClaims_AndNotWithGoodClaims()
    {
        await using var host = Host();
        var weak = Client(host, null, null);
        var strong = Client(host, "mfa", Now);

        foreach (var (method, pattern) in StepUpRoutes.Protected)
        {
            var refused = await weak.SendAsync(Request(method, pattern), Ct);
            Assert.True(refused.StatusCode == HttpStatusCode.Unauthorized, $"{method} {pattern} without claims answered {(int)refused.StatusCode}");
            Assert.Contains("insufficient_user_authentication", string.Join(' ', refused.Headers.GetValues("WWW-Authenticate")));

            var allowed = await strong.SendAsync(Request(method, pattern), Ct);
            Assert.True(allowed.StatusCode != HttpStatusCode.Unauthorized, $"{method} {pattern} with good claims answered 401");
            Assert.True(allowed.StatusCode != HttpStatusCode.Forbidden, $"{method} {pattern} with good claims answered 403");
        }
    }

    [Fact]
    public async Task EveryProtectedEntry_IsARealEndpoint_AndNoOtherRouteIsMatchedByAccident()
    {
        await using var host = Host();
        var endpoints = host.Factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();

        foreach (var (method, pattern) in StepUpRoutes.Protected)
        {
            var matches = endpoints.Count(e =>
                e.RoutePattern.RawText == pattern
                && (e.Metadata.GetMetadata<IHttpMethodMetadata>()?.HttpMethods.Contains(method, StringComparer.OrdinalIgnoreCase) ?? false));
            Assert.True(matches == 1, $"{method} {pattern} matches {matches} endpoints; fix the table in StepUpRoutes");
        }
    }

    [Fact]
    public async Task AnUnprotectedRoute_IsUnaffected_ByMissingClaims()
    {
        await using var host = Host();

        var response = await Client(host, null, null).GetAsync("/v1/issuers", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task WhenDisabled_AProtectedRoute_NeedsNoClaims()
    {
        await using var host = Host(enabled: false);

        var response = await Client(host, null, null).SendAsync(Probe(), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ACallerWithoutThePermission_Gets403_NotTheChallenge()
    {
        await using var host = Host();

        var response = await host.Role("nobody").SendAsync(Probe(), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("WWW-Authenticate"));
    }

    [Fact]
    public async Task AnAnonymousCaller_Gets401_WithoutTheStepUpChallenge()
    {
        await using var host = Host();

        var response = await host.Anonymous().SendAsync(Probe(), Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("insufficient_user_authentication", string.Join(' ', response.Headers.TryGetValues("WWW-Authenticate", out var v) ? v : []));
    }
}
