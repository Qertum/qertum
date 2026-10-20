using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Acme;

/// <summary>
/// Rate limiting for the ACME surface. ACME clients poll: an order or authorization is fetched every
/// few seconds while a challenge is validated, and every request needs a fresh nonce first. Metering
/// that traffic with the same allowance as account and order creation means either throttling a
/// correctly-behaving client or leaving the expensive operations effectively unmetered, so the two
/// classes get separate windows.
/// </summary>
/// <summary>The <c>Acme:RateLimits</c> section.</summary>
public sealed class AcmeRateLimitOptions
{
    public const string SectionName = "Acme:RateLimits";

    public int PollingPermitLimit { get; set; } = 300;
    public int PollingWindowSeconds { get; set; } = 60;
    public int WritePermitLimit { get; set; } = 20;
    public int WriteWindowSeconds { get; set; } = 60;
}

public static class AcmeRateLimiting
{
    /// <summary>Nonce fetches and status polling — high volume by protocol design.</summary>
    public const string PollingPolicy = "acme-polling";

    /// <summary>Account creation, order creation, finalize, revocation, key rollover.</summary>
    public const string WritePolicy = "acme-write";

    public static IServiceCollection AddAcmeRateLimiting(this IServiceCollection services)
    {
        services.AddOptions<AcmeRateLimitOptions>()
            .BindConfiguration(AcmeRateLimitOptions.SectionName)
            .Validate(o => o.PollingPermitLimit >= 1, "Acme:RateLimits:PollingPermitLimit must be at least 1.")
            .Validate(o => o.PollingWindowSeconds >= 1, "Acme:RateLimits:PollingWindowSeconds must be at least 1.")
            .Validate(o => o.WritePermitLimit >= 1, "Acme:RateLimits:WritePermitLimit must be at least 1.")
            .Validate(o => o.WriteWindowSeconds >= 1, "Acme:RateLimits:WriteWindowSeconds must be at least 1.")
            .ValidateOnStart();

        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<AcmeRateLimitOptions>>((options, acme) =>
        {
            var pollingLimit = acme.Value.PollingPermitLimit;
            var pollingWindow = acme.Value.PollingWindowSeconds;
            var writeLimit = acme.Value.WritePermitLimit;
            var writeWindow = acme.Value.WriteWindowSeconds;

            options.AddPolicy(PollingPolicy, context => PartitionFor(context, pollingLimit, pollingWindow));
            options.AddPolicy(WritePolicy, context => PartitionFor(context, writeLimit, writeWindow));

            // RFC 8555 §6.6: a client that is being limited should be told so in the problem document
            // it already knows how to read, and told when to come back. A bare 429 with no body sends
            // a well-behaved client into a retry loop it cannot pace.
            options.OnRejected = async (context, ct) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.ContentType = "application/problem+json";

                // The sliding-window limiter does not always publish RetryAfter metadata, so fall
                // back to the window the request was measured against — a client told nothing retries
                // immediately and burns the next window too.
                var retrySeconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
                    ? (int)retryAfter.TotalSeconds
                    : context.HttpContext.Items.TryGetValue(RetryAfterItemKey, out var hint) && hint is int seconds
                        ? seconds
                        : pollingWindow;
                context.HttpContext.Response.Headers.RetryAfter = retrySeconds.ToString();

                await context.HttpContext.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    type = "urn:ietf:params:acme:error:rateLimited",
                    title = "rateLimited",
                    status = StatusCodes.Status429TooManyRequests,
                    detail = "Too many requests; slow down and retry later."
                }), ct);
            };
        });

        return services;
    }

    private const string RetryAfterItemKey = "acme:retry-after-seconds";

    /// <summary>
    /// Partitioned by client address. ACME requests carry no bearer token and the account they belong
    /// to is only known after the JWS is parsed, which is work this limiter exists to avoid doing for
    /// a flood of requests.
    /// </summary>
    private static RateLimitPartition<string> PartitionFor(HttpContext context, int permitLimit, int windowSeconds)
    {
        // Recorded per request so a rejection can name the window this particular endpoint class was
        // measured against; OnRejected is global and cannot tell the two policies apart otherwise.
        context.Items[RetryAfterItemKey] = windowSeconds;

        return RateLimitPartition.GetSlidingWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                SegmentsPerWindow = 6,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0
            });
    }
}
