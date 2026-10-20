using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Webhooks;

namespace Qertum.Tests;

// Records each request the fake HTTP endpoint receives, and lets the test decide the
// response per-request without needing a live HTTP server.
file sealed class RecordingHandler(Func<int, HttpStatusCode> responder) : HttpMessageHandler
{
    private int _callCount;
    public List<(string? EventHeader, string? DeliveryIdHeader, string? SignatureHeader, string? Body, string? Url, bool HasPolicy)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        request.Headers.TryGetValues("X-Webhook-Event", out var eventValues);
        request.Headers.TryGetValues("X-Webhook-Delivery", out var deliveryValues);
        request.Headers.TryGetValues("X-Webhook-Signature", out var signatureValues);

        Requests.Add((eventValues?.FirstOrDefault(), deliveryValues?.FirstOrDefault(), signatureValues?.FirstOrDefault(),
            body, request.RequestUri?.ToString(), request.Options.TryGetValue(WebhookDestinationHttpHandler.PolicyKey, out _)));

        var callNumber = Interlocked.Increment(ref _callCount);
        return new HttpResponseMessage(responder(callNumber));
    }
}

public sealed class WebhookDeliveryServiceTests
{
    [Fact]
    public async Task SuccessfulDelivery_MarksDeliveredAndSignsPayload()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();

        var webhook = await scope.SeedWebhookAsync(secret: "top-secret");
        var delivery = await scope.SeedDeliveryAsync(webhook.Id, payload: """{"event":"Issued"}""");

        var handler = new RecordingHandler(_ => HttpStatusCode.OK);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Delivered", result.Status);
        Assert.Equal(1, result.AttemptCount);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("Issued", request.EventHeader);
        Assert.Equal(delivery.Id.ToString(), request.DeliveryIdHeader);
        Assert.Equal("""{"event":"Issued"}""", request.Body);

        var expectedSignature = "sha256=" + Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes("top-secret"), Encoding.UTF8.GetBytes(delivery.Payload))).ToLowerInvariant();
        Assert.Equal(expectedSignature, request.SignatureHeader);
    }

    [Fact]
    public async Task NoSecret_NoSignatureHeaderSent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();

        var webhook = await scope.SeedWebhookAsync(secret: null);
        var delivery = await scope.SeedDeliveryAsync(webhook.Id);

        var handler = new RecordingHandler(_ => HttpStatusCode.OK);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var request = Assert.Single(handler.Requests);
        Assert.Null(request.SignatureHeader);
    }

    [Fact]
    public async Task TransientFailure_SchedulesBackoffAndStaysPending()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();

        var webhook = await scope.SeedWebhookAsync();
        var delivery = await scope.SeedDeliveryAsync(webhook.Id);

        var before = DateTime.UtcNow;
        var handler = new RecordingHandler(_ => HttpStatusCode.InternalServerError);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Pending", result.Status);
        Assert.Equal(1, result.AttemptCount);
        Assert.Equal("HTTP 500", result.LastErrorMessage);
        // Exponential backoff: min(2^1 * 30s, 24h) = 60s.
        Assert.InRange(result.NextAttemptAfterUtc, before.AddSeconds(59), before.AddSeconds(70));
    }

    [Fact]
    public async Task FifthFailedAttempt_PermanentlyFails()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();

        var webhook = await scope.SeedWebhookAsync();
        // Already failed 4 times; this poll's failure is the 5th (MaxRetries) attempt.
        var delivery = await scope.SeedDeliveryAsync(webhook.Id, attemptCount: 4);

        var handler = new RecordingHandler(_ => HttpStatusCode.InternalServerError);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Failed", result.Status);
        Assert.Equal(5, result.AttemptCount);
    }

    [Fact]
    public async Task Metrics_CountDeliveredRetryAndFailedAttemptsByOutcome()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = new OperationsMetrics(meters);

        var webhook = await scope.SeedWebhookAsync();
        // One poll handles every due row, so each delivery is seeded just before its own poll.
        var delivered = await scope.SeedDeliveryAsync(webhook.Id);
        await scope.RunOnePollAsync(new RecordingHandler(_ => HttpStatusCode.OK), delivered.Id, ct, metrics);

        var retrying = await scope.SeedDeliveryAsync(webhook.Id);
        await scope.RunOnePollAsync(new RecordingHandler(_ => HttpStatusCode.InternalServerError), retrying.Id, ct, metrics);

        var failing = await scope.SeedDeliveryAsync(webhook.Id, attemptCount: 4);
        await scope.RunOnePollAsync(new RecordingHandler(_ => HttpStatusCode.InternalServerError), failing.Id, ct, metrics);

        Assert.Equal(1, recorder.Sum("ca.webhook.deliveries", ("outcome", "delivered")));
        Assert.Equal(1, recorder.Sum("ca.webhook.deliveries", ("outcome", "retry")));
        Assert.Equal(1, recorder.Sum("ca.webhook.deliveries", ("outcome", "failed")));
    }

    [Fact]
    public async Task Metrics_CountDisabledWebhookAsFailed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = new OperationsMetrics(meters);

        var webhook = await scope.SeedWebhookAsync(isEnabled: false);
        var delivery = await scope.SeedDeliveryAsync(webhook.Id);

        await scope.RunOnePollAsync(new RecordingHandler(_ => HttpStatusCode.OK), delivery.Id, ct, metrics);

        Assert.Equal(1, recorder.Sum("ca.webhook.deliveries", ("outcome", "failed")));
    }

    [Fact]
    public async Task DisabledWebhook_DeliveryFailsWithoutHttpCall()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();

        var webhook = await scope.SeedWebhookAsync(isEnabled: false);
        var delivery = await scope.SeedDeliveryAsync(webhook.Id);

        var handler = new RecordingHandler(_ => HttpStatusCode.OK);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Failed", result.Status);
        Assert.Equal("Webhook is disabled.", result.LastErrorMessage);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ResolvedUrlIsCheckedAndUsedInsteadOfWebhookUrl()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var webhook = await scope.SeedWebhookAsync(url: "http://127.0.0.1/private");
        var delivery = await scope.SeedDeliveryAsync(webhook.Id, resolvedUrl: "https://hook.invalid/event/issued");
        var handler = new RecordingHandler(_ => HttpStatusCode.OK);

        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        Assert.Equal("Delivered", (await scope.GetDeliveryAsync(delivery.Id, ct)).Status);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://hook.invalid/event/issued", request.Url);
        Assert.True(request.HasPolicy);
    }

    [Theory]
    [InlineData("http://127.0.0.1/private")]
    [InlineData("https://hook.invalid/{unresolved}")]
    [InlineData("https://hook.invalid/partial#fragment")]
    public async Task RejectedResolvedUrlConsumesAnAttemptWithoutSending(string resolvedUrl)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var webhook = await scope.SeedWebhookAsync();
        var delivery = await scope.SeedDeliveryAsync(webhook.Id, resolvedUrl: resolvedUrl);
        var handler = new RecordingHandler(_ => HttpStatusCode.OK);

        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Pending", result.Status);
        Assert.Equal(1, result.AttemptCount);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task OversizedTemplateExpansionFailsWithoutSendingATruncatedUrl()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var template = "https://hook.invalid/?a=" + new string('x', 1000) +
            string.Concat(Enumerable.Repeat("&n={resourceName}", 12));
        var resolvedUrl = WebhookUrlTemplate.Resolve(template,
            new Dictionary<string, string?> { ["resourceName"] = new string('y', 256) });
        var webhook = await scope.SeedWebhookAsync(url: template);
        var delivery = await scope.SeedDeliveryAsync(webhook.Id, resolvedUrl: resolvedUrl);
        var handler = new RecordingHandler(_ => HttpStatusCode.OK);

        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal("Pending", result.Status);
        Assert.Equal(1, result.AttemptCount);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ChangedPolicyBlocksNextAttempt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await WebhookTestScope.CreateAsync();
        var webhook = await scope.SeedWebhookAsync();
        var delivery = await scope.SeedDeliveryAsync(webhook.Id);
        var handler = new RecordingHandler(_ => HttpStatusCode.InternalServerError);

        await scope.RunOnePollAsync(handler, delivery.Id, ct);
        Assert.Single(handler.Requests);
        await scope.SetPublicModeAsync(WebhookPublicMode.ListedPublic);
        await scope.MakeDueAsync(delivery.Id);
        await scope.RunOnePollAsync(handler, delivery.Id, ct);

        Assert.Single(handler.Requests);
        var result = await scope.GetDeliveryAsync(delivery.Id, ct);
        Assert.Equal(2, result.AttemptCount);
        Assert.Equal("Pending", result.Status);
    }

    // Wraps a SQLite-backed WebhookDeliveryService: seeds rows through one DbContext,
    // drives one poll cycle of the real service (via the inherited
    // BackgroundService.StartAsync/StopAsync) concurrently with polling reads from
    // another, and reads results back through a fresh DbContext (matching the real
    // deployment, where the service and readers use separate scopes).
    //
    // Uses SQLite's named shared-cache in-memory mode (a connection *string*, not one
    // shared live SqliteConnection object) so each DbContext opens its own connection
    // and concurrent access goes through SQLite's normal cross-connection locking
    // instead of two DbContexts racing to use a single native connection handle
    // (which throws "database is locked" under the polling in RunOnePollAsync below).
    // The anchor connection just keeps the shared in-memory DB alive for the test.
    private sealed class WebhookTestScope(SqliteConnection anchorConnection, IServiceScopeFactory scopeFactory) : IAsyncDisposable
    {
        public static async Task<WebhookTestScope> CreateAsync()
        {
            var connectionString = $"Data Source=file:webhooktest_{Guid.NewGuid():N};Mode=Memory;Cache=Shared";

            var anchorConnection = new SqliteConnection(connectionString);
            await anchorConnection.OpenAsync();

            var services = new ServiceCollection();
            services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            services.AddScoped(sp =>
            {
                var options = new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connectionString).Options;
                return new CertificateRequestDbContext(options, sp.GetRequiredService<IDataProtectionProvider>());
            });
            services.AddScoped<IWebhookDestinationPolicyService, WebhookDestinationPolicyService>();
            var provider = services.BuildServiceProvider();

            await using (var scope = provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
                await db.Database.EnsureCreatedAsync();
                db.WebhookDestinationPolicyStates.Add(new WebhookDestinationPolicyState
                {
                    Id = 1, Initialized = true, JsonPublicMode = WebhookPublicMode.AnyPublic
                });
                await db.SaveChangesAsync();
            }

            return new WebhookTestScope(anchorConnection, provider.GetRequiredService<IServiceScopeFactory>());
        }

        public async Task<Webhook> SeedWebhookAsync(string? secret = "shared-secret", bool isEnabled = true,
            string url = "http://webhook.invalid/receive")
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var webhook = new Webhook
            {
                Id = Guid.NewGuid(),
                Name = "test-webhook",
                Url = url,
                Secret = secret,
                EventsJson = """["Issued"]""",
                IsEnabled = isEnabled,
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            };
            db.Webhooks.Add(webhook);
            await db.SaveChangesAsync();
            return webhook;
        }

        public async Task<WebhookDelivery> SeedDeliveryAsync(WebhookId webhookId, string payload = """{"event":"Issued"}""",
            int attemptCount = 0, string? resolvedUrl = null)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var delivery = new WebhookDelivery
            {
                Id = Guid.NewGuid(),
                WebhookId = webhookId,
                EventType = "Issued",
                Payload = payload,
                ResolvedUrl = resolvedUrl,
                Status = "Pending",
                AttemptCount = attemptCount,
                NextAttemptAfterUtc = DateTime.UtcNow.AddSeconds(-1),
                CreatedAtUtc = DateTime.UtcNow
            };
            db.WebhookDeliveries.Add(delivery);
            await db.SaveChangesAsync();
            return delivery;
        }

        public async Task<WebhookDelivery> GetDeliveryAsync(Guid id, CancellationToken ct)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            return await db.WebhookDeliveries.SingleAsync(d => d.Id == id, ct);
        }

        public async Task SetPublicModeAsync(WebhookPublicMode mode)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var state = await db.WebhookDestinationPolicyStates.SingleAsync();
            state.JsonPublicMode = mode;
            await db.SaveChangesAsync();
        }

        public async Task MakeDueAsync(Guid id)
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var delivery = await db.WebhookDeliveries.SingleAsync(d => d.Id == id);
            delivery.NextAttemptAfterUtc = DateTime.UtcNow.AddSeconds(-1);
            await db.SaveChangesAsync();
        }

        // Starts the real WebhookDeliveryService with a slow poll interval (so it only
        // scans once during the test window below), waits for the seeded delivery row
        // to change, then stops it.
        public async Task RunOnePollAsync(HttpMessageHandler handler, Guid deliveryId, CancellationToken ct,
            OperationsMetrics? metrics = null)
        {
            var options = Microsoft.Extensions.Options.Options.Create(new WebhookDeliveryOptions { DeliveryPollIntervalSeconds = 60 });
            using var httpClient = new HttpClient(handler);
            var service = new WebhookDeliveryService(
                scopeFactory, NullLogger<WebhookDeliveryService>.Instance, options, httpClient, metrics);

            var initial = await GetDeliveryAsync(deliveryId, ct);

            await service.StartAsync(ct);
            try
            {
                var deadline = DateTime.UtcNow.AddSeconds(5);
                while (DateTime.UtcNow < deadline)
                {
                    try
                    {
                        var current = await GetDeliveryAsync(deliveryId, ct);
                        if (current.AttemptCount != initial.AttemptCount || current.Status != initial.Status)
                            return;
                    }
                    catch (SqliteException)
                    {
                        // Transient contention against the shared in-memory connection while
                        // the service's own poll is mid-write; just retry.
                    }

                    await Task.Delay(20, ct);
                }

                throw new TimeoutException($"Delivery {deliveryId} did not change state within the test timeout.");
            }
            finally
            {
                await service.StopAsync(ct);
            }
        }

        public async ValueTask DisposeAsync() => await anchorConnection.DisposeAsync();
    }
}
