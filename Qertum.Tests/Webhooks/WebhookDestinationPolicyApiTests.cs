using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;
using Qertum.Tests.Roles;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookDestinationPolicyApiTests
{
    [Fact]
    public async Task AdminCanAddDisableAndListInternalRule()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var create = await admin.PostAsJsonAsync("/v1/webhook-destinations/rules", new
        {
            kind = "Internal", scheme = "https", host = "intranet.invalid", port = 443,
            allowedIpAddresses = new[] { "10.0.0.7" }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
        using var created = JsonDocument.Parse(await create.Content.ReadAsStringAsync(ct));
        var id = created.RootElement.GetProperty("id").GetGuid();

        var disable = await admin.PutAsJsonAsync($"/v1/webhook-destinations/rules/{id}/enabled",
            new { enabled = false }, ct);
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);

        using var response = JsonDocument.Parse(await admin.GetStringAsync("/v1/webhook-destinations", ct));
        Assert.Equal("AnyPublic", response.RootElement.GetProperty("publicMode").GetString());
        var rule = Assert.Single(response.RootElement.GetProperty("rules").EnumerateArray());
        Assert.Equal("intranet.invalid", rule.GetProperty("host").GetString());
        Assert.Equal("Admin", rule.GetProperty("source").GetString());
        Assert.False(rule.GetProperty("enabled").GetBoolean());
    }

    [Fact]
    public async Task SettingsEditorCannotReadOrWriteDestinationPolicy()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await RolePermissionsApiTests.SeedRoleAsync(factory, "editors", [AppPermissions.SettingsEdit], ct);
        using var editor = RolePermissionsApiTests.AsRole(factory, "editors");

        Assert.Equal(HttpStatusCode.Forbidden,
            (await editor.GetAsync("/v1/webhook-destinations", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await editor.PutAsJsonAsync("/v1/webhook-destinations/mode", new { publicMode = "AnyPublic" }, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await editor.PostAsJsonAsync("/v1/webhook-destinations/rules", new
            {
                kind = "Internal", scheme = "https", host = "internal.invalid", port = 443,
                allowedIpAddresses = new[] { "10.0.0.7" }
            }, ct)).StatusCode);
    }

    [Theory]
    [InlineData("*.invalid", "10.0.0.7")]
    [InlineData("internal.invalid", "169.254.169.254")]
    [InlineData("internal.invalid", "10.0.0.0/8")]
    public async Task InvalidInternalRuleIsRejected(string host, string ip)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/webhook-destinations/rules", new
        {
            kind = "Internal", scheme = "https", host, port = 443,
            allowedIpAddresses = new[] { ip }
        }, ct);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task WebhookSaveRejectsBlockedLiteralAndUnlistedPublicOrigin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var blocked = await admin.PostAsJsonAsync("/v1/webhooks", Webhook("http://127.0.0.1/hook"), ct);
        Assert.Equal(HttpStatusCode.BadRequest, blocked.StatusCode);

        var mode = await admin.PutAsJsonAsync("/v1/webhook-destinations/mode",
            new { publicMode = "ListedPublic" }, ct);
        Assert.Equal(HttpStatusCode.OK, mode.StatusCode);

        var unlisted = await admin.PostAsJsonAsync("/v1/webhooks", Webhook("https://other.invalid/hook"), ct);
        Assert.Equal(HttpStatusCode.BadRequest, unlisted.StatusCode);

        var added = await admin.PostAsJsonAsync("/v1/webhook-destinations/rules", new
        {
            kind = "Public", scheme = "https", host = "allowed.invalid", port = 443,
            allowedIpAddresses = Array.Empty<string>()
        }, ct);
        Assert.Equal(HttpStatusCode.Created, added.StatusCode);

        var allowed = await admin.PostAsJsonAsync("/v1/webhooks", Webhook("https://allowed.invalid/{event}"), ct);
        Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
    }

    private static object Webhook(string url) => new
    {
        name = "policy-test", url, family = "CertificateRequest", eventsJson = "[]", isEnabled = true
    };

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }
}
