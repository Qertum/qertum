using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Qertum.Services.Est;

/// <summary>
/// Counts one <c>ca.est.enrollments</c> measurement per enrollment request from the response it
/// produced, so every refusal path is covered without touching each <c>return</c> in the handlers.
/// Requests the rate limiter rejects never reach the endpoint; the built-in ASP.NET Core rate limiter
/// metrics cover those.
/// </summary>
internal static class EstEnrollmentMetricsFilter
{
    /// <summary>Operation tag for <c>/simpleenroll</c>.</summary>
    public const string Enroll = "enroll";

    /// <summary>Operation tag for <c>/simplereenroll</c>.</summary>
    public const string Reenroll = "reenroll";

    public static RouteHandlerBuilder CountEnrollments(this RouteHandlerBuilder builder, string operation) =>
        builder.AddEndpointFilter(async (context, next) =>
        {
            var metrics = context.HttpContext.RequestServices.GetService<ProtocolMetrics>();
            try
            {
                var result = await next(context);
                metrics?.EstEnrollments.Add(1,
                    new KeyValuePair<string, object?>("operation", operation),
                    new KeyValuePair<string, object?>("outcome", OutcomeFor((result as IStatusCodeHttpResult)?.StatusCode ?? StatusCodes.Status200OK)));
                return result;
            }
            catch
            {
                metrics?.EstEnrollments.Add(1,
                    new KeyValuePair<string, object?>("operation", operation),
                    new KeyValuePair<string, object?>("outcome", "error"));
                throw;
            }
        });

    internal static string OutcomeFor(int statusCode) => statusCode switch
    {
        StatusCodes.Status200OK => "issued",
        StatusCodes.Status202Accepted => "pending",
        StatusCodes.Status401Unauthorized or StatusCodes.Status403Forbidden => "unauthorized",
        >= 500 => "error",
        _ => "refused"
    };
}
