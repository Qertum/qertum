using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Qertum.Services.Auth;

namespace Qertum.ApiService;

/// <summary>The <c>RateLimiting</c> section: the sliding window on <c>/certificate-requests/*</c>.</summary>
public sealed class ApiRateLimitOptions
{
    public const string SectionName = "RateLimiting";

    public int PermitLimit { get; set; } = 100;
    public int WindowSeconds { get; set; } = 60;
    public int QueueLimit { get; set; } = 10;
}

public static class ApiRateLimiting
{
    /// <summary>The policy name routes opt into with <c>RequireRateLimiting</c>.</summary>
    public const string PolicyName = "api";

    /// <summary>
    /// Registers the <c>api</c> policy from validated options, so a bad limit stops the host at startup
    /// instead of being read ad hoc when the limiter is first built.
    /// </summary>
    public static IServiceCollection AddApiRateLimiting(this IServiceCollection services)
    {
        services.AddOptions<ApiRateLimitOptions>()
            .BindConfiguration(ApiRateLimitOptions.SectionName)
            .Validate(o => o.PermitLimit >= 1, "RateLimiting:PermitLimit must be at least 1.")
            .Validate(o => o.WindowSeconds >= 1, "RateLimiting:WindowSeconds must be at least 1.")
            .Validate(o => o.QueueLimit >= 0, "RateLimiting:QueueLimit cannot be negative.")
            .ValidateOnStart();

        services.AddRateLimiter(_ => { });
        services.AddOptions<RateLimiterOptions>().Configure<IOptions<ApiRateLimitOptions>>((options, api) =>
        {
            var limits = api.Value;
            // One window per caller, as documented: a single shared window let one client, whatever its
            // permissions, refuse the API to everyone else. The limiter runs after authentication, so the
            // token's subject is known; a request without one falls back to the client address.
            options.AddPolicy(PolicyName, context => RateLimitPartition.GetSlidingWindowLimiter(
                PartitionKey(context),
                _ => new SlidingWindowRateLimiterOptions
                {
                    PermitLimit = limits.PermitLimit,
                    Window = TimeSpan.FromSeconds(limits.WindowSeconds),
                    SegmentsPerWindow = 6,
                    QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                    QueueLimit = limits.QueueLimit
                }));
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });
        return services;
    }

    private static string PartitionKey(HttpContext context) =>
        context.RequestServices.GetService<IIdentityClaimsMapper>()?.GetSubject(context.User) is { Length: > 0 } subject
            ? "sub:" + subject
            : "ip:" + context.Connection.RemoteIpAddress;
}
