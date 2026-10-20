using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Est;

/// <summary>
/// Rate limiting for the EST surface. <c>/simpleenroll</c> runs a full PBKDF2 verification
/// (<see cref="IEstEnrollmentCredentialService.CheckAsync"/>) for every request that names a known
/// username, before any authentication has succeeded — unmetered, that is both an online
/// password-guessing oracle and a CPU-exhaustion vector. Unlike ACME, EST has no polling-heavy
/// pattern that needs a separate, looser allowance, so one policy covers both enrollment endpoints.
/// Modeled on <see cref="Qertum.Services.Acme.AcmeRateLimiting"/>.
/// </summary>
/// <summary>The <c>Est</c> section.</summary>
public sealed class EstOptions
{
    public const string SectionName = "Est";

    /// <summary>
    /// Refuse <c>/simpleenroll</c> over plaintext, where HTTP Basic sends the password in the clear.
    /// Turn off only when TLS is terminated at a trusted reverse proxy.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    public EstRateLimitOptions RateLimits { get; set; } = new();
}

/// <summary>The <c>Est:RateLimits</c> section.</summary>
public sealed class EstRateLimitOptions
{
    public int PermitLimit { get; set; } = 20;
    public int WindowSeconds { get; set; } = 60;
}

public static class EstRateLimiting
{
    public const string PolicyName = "est-enroll";

    /// <summary>Also binds and validates <see cref="EstOptions"/>, which the enrollment endpoints read.</summary>
    public static IServiceCollection AddEstRateLimiting(this IServiceCollection services)
    {
        services.AddOptions<EstOptions>()
            .BindConfiguration(EstOptions.SectionName)
            .Validate(o => o.RateLimits.PermitLimit >= 1, "Est:RateLimits:PermitLimit must be at least 1.")
            .Validate(o => o.RateLimits.WindowSeconds >= 1, "Est:RateLimits:WindowSeconds must be at least 1.")
            .ValidateOnStart();

        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<EstOptions>>((options, est) =>
        {
            var permitLimit = est.Value.RateLimits.PermitLimit;
            var windowSeconds = est.Value.RateLimits.WindowSeconds;

            options.AddPolicy(PolicyName, context => PartitionFor(context, permitLimit, windowSeconds));

            options.OnRejected = async (context, ct) =>
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

                var retrySeconds = context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter)
                    ? (int)retryAfter.TotalSeconds
                    : windowSeconds;
                context.HttpContext.Response.Headers.RetryAfter = retrySeconds.ToString();

                await context.HttpContext.Response.WriteAsync("Too many requests; slow down and retry later.", ct);
            };
        });

        return services;
    }

    /// <summary>
    /// Partitioned by client address: the caller's identity is only known after the expensive
    /// verification work this limiter exists to bound, same reasoning as ACME's partitioning.
    /// </summary>
    private static RateLimitPartition<string> PartitionFor(HttpContext context, int permitLimit, int windowSeconds)
    {
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
