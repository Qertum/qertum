using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    [Fact]
    public async Task PostTemplateFamilyWebhook_IsCreatedAndReportsItsFamily()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "template-hook",
            url = "https://h.invalid/t?e={event}&n={templateName}",
            family = "Template",
            eventsJson = "[]",
            isEnabled = true
        }, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<Webhook>(ct))!;
        Assert.Equal(WebhookEventFamily.Template, created.Family);

        var fetched = (await admin.GetFromJsonAsync<Webhook>($"/v1/webhooks/{(Guid)created.Id}", ct))!;
        Assert.Equal(WebhookEventFamily.Template, fetched.Family);
    }

    [Fact]
    public async Task TheSigningSecretIsNeverReadBack_OnlyWhetherOneIsSet()
    {
        // A settings.edit holder could read every receiver's HMAC secret and forge deliveries to it
        // without changing anything. Like ACME EAB keys: write-only, no read-back.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        const string secret = "s3cr3t-hmac-key-value";

        var response = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "signed-hook",
            url = "https://h.invalid/s",
            family = "CertificateRequest",
            eventsJson = "[]",
            secret,
            isEnabled = true
        }, ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var createdBody = await response.Content.ReadAsStringAsync(ct);
        var created = System.Text.Json.JsonSerializer.Deserialize<Webhook>(createdBody, System.Text.Json.JsonSerializerOptions.Web)!;

        var list = await admin.GetStringAsync("/v1/webhooks", ct);
        var single = await admin.GetStringAsync($"/v1/webhooks/{(Guid)created.Id}", ct);

        foreach (var body in new[] { createdBody, list, single })
        {
            Assert.DoesNotContain(secret, body);
            Assert.Contains("\"hasSecret\":true", body);
        }
    }

    [Fact]
    public async Task PostEventFromAnotherFamily_IsRejectedAndNamesTheFamilysEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "confused-hook",
            url = "https://h.invalid/t",
            family = "Template",
            eventsJson = """["Issued"]""",
            isEnabled = true
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("TemplateCreated", await response.Content.ReadAsStringAsync(ct));
    }

    [Fact]
    public async Task PostPlaceholderFromAnotherFamily_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "policy-hook",
            url = "https://h.invalid/p?cn={commonName}",
            family = "Policy",
            eventsJson = "[]",
            isEnabled = true
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("commonName", await response.Content.ReadAsStringAsync(ct));
    }

    [Fact]
    public async Task PostWithNoFamily_DefaultsToCertificateRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "legacy-client-hook",
            url = "https://h.invalid/legacy",
            eventsJson = """["Issued","Revoked"]""",
            isEnabled = true
        }, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<Webhook>(ct))!;
        Assert.Equal(WebhookEventFamily.CertificateRequest, created.Family);
    }

    [Fact]
    public async Task ChangingFamilyRevalidatesTheUrl()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var createResponse = await admin.PostAsJsonAsync("/v1/webhooks", new
        {
            name = "moving-hook",
            url = "https://h.invalid/c?cn={commonName}",
            family = "CertificateRequest",
            eventsJson = "[]",
            isEnabled = true
        }, ct);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = (await createResponse.Content.ReadFromJsonAsync<Webhook>(ct))!;

        // The URL was valid for CertificateRequest; Settings carries no commonName.
        var response = await admin.PutAsJsonAsync($"/v1/webhooks/{(Guid)created.Id}", new
        {
            name = "moving-hook",
            url = "https://h.invalid/c?cn={commonName}",
            family = "Settings",
            eventsJson = "[]",
            isEnabled = true
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("commonName", await response.Content.ReadAsStringAsync(ct));
    }
}
