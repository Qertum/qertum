using System.Net;
using System.Net.Http.Json;
using Qertum.Services;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookDestinationClientTests
{
    [Fact]
    public async Task ClientUsesDestinationRoutesAndContractBodies()
    {
        var requests = new List<(HttpMethod Method, string Path, string? Body)>();
        using var http = new HttpClient(new RecordingHandler(async request =>
        {
            requests.Add((request.Method, request.RequestUri!.AbsolutePath,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)));
            if (request.Method == HttpMethod.Delete) return new HttpResponseMessage(HttpStatusCode.NoContent);
            object response = request.RequestUri.AbsolutePath.EndsWith("/rules") && request.Method == HttpMethod.Post
                ? new WebhookDestinationRuleResponse { Id = Guid.NewGuid(), Source = "Admin", Host = "hook.example", Port = 443 }
                : request.RequestUri.AbsolutePath.EndsWith("/enabled")
                    ? new WebhookDestinationRuleResponse { Id = Guid.NewGuid(), Source = "Admin", Host = "hook.example", Port = 443 }
                    : new WebhookDestinationPolicyResponse { Initialized = true, PublicMode = WebhookPublicMode.ListedPublic };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(response) };
        })) { BaseAddress = new Uri("https://api.example/") };
        var client = new CertificateRequestsApiClient(http);
        var id = Guid.NewGuid();

        Assert.Equal(WebhookPublicMode.ListedPublic, (await client.GetWebhookDestinationPolicyAsync(TestContext.Current.CancellationToken)).PublicMode);
        await client.SetWebhookDestinationPublicModeAsync(WebhookPublicMode.ListedPublic, TestContext.Current.CancellationToken);
        await client.AddWebhookDestinationRuleAsync(new SaveWebhookDestinationRuleRequest
        {
            Kind = WebhookDestinationRuleKind.Internal, Scheme = "https", Host = "hook.example", Port = 443,
            AllowedIpAddresses = ["10.0.0.7"]
        }, TestContext.Current.CancellationToken);
        await client.SetWebhookDestinationRuleEnabledAsync(id, false, TestContext.Current.CancellationToken);
        await client.DeleteWebhookDestinationRuleAsync(id, TestContext.Current.CancellationToken);

        Assert.Equal(["/v1/webhook-destinations", "/v1/webhook-destinations/mode",
            "/v1/webhook-destinations/rules", $"/v1/webhook-destinations/rules/{id}/enabled",
            $"/v1/webhook-destinations/rules/{id}"], requests.Select(r => r.Path));
        Assert.Contains("\"publicMode\":\"ListedPublic\"", requests[1].Body);
        Assert.Contains("\"allowedIpAddresses\":[\"10.0.0.7\"]", requests[2].Body);
        Assert.Contains("\"enabled\":false", requests[3].Body);
    }

    [Fact]
    public async Task ClientPreservesServerProblem()
    {
        using var http = new HttpClient(new RecordingHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = JsonContent.Create(new { title = "Forbidden", detail = "Admin role required." })
        }))) { BaseAddress = new Uri("https://api.example/") };
        var client = new CertificateRequestsApiClient(http);

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetWebhookDestinationPolicyAsync(TestContext.Current.CancellationToken));
        Assert.Equal(HttpStatusCode.Forbidden, problem.StatusCode);
    }

    [Fact]
    public async Task ClientSurfacesValidationMessagesWhenTheProblemHasNoDetail()
    {
        using var http = new HttpClient(new RecordingHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = JsonContent.Create(new
            {
                title = "One or more validation errors occurred.",
                errors = new Dictionary<string, string[]> { ["Url"] = ["Url must be an absolute http or https URL."] }
            })
        }))) { BaseAddress = new Uri("https://api.example/") };
        var client = new CertificateRequestsApiClient(http);

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetWebhookDestinationPolicyAsync(TestContext.Current.CancellationToken));

        Assert.Equal("Url must be an absolute http or https URL.", problem.Message);
        Assert.Equal("One or more validation errors occurred.", problem.Title);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => respond(request);
    }
}
