using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;

namespace Qertum.Services.Auth;

/// <summary>
/// Refuses a protected operation (<see cref="StepUpRoutes"/>) whose token fails <see cref="StepUpEvaluator"/>. Runs after
/// authorization, so a caller who lacks the permission has already been answered 403 and never learns of step-up.
/// The answer is an RFC 9470 challenge: 401 with <c>WWW-Authenticate: Bearer error="insufficient_user_authentication"</c>.
/// </summary>
public sealed class StepUpMiddleware(RequestDelegate next)
{
    /// <summary>Applies the check to the matched endpoint, then continues.</summary>
    public async Task InvokeAsync(HttpContext context, StepUpEvaluator evaluator, ILogger<StepUpMiddleware> logger)
    {
        if (evaluator.Options.Enabled
            && context.GetEndpoint() is RouteEndpoint endpoint
            && StepUpRoutes.IsProtected(context.Request.Method, endpoint.RoutePattern.RawText))
        {
            var result = evaluator.Evaluate(context.User);
            if (result != StepUpResult.Satisfied)
            {
                logger.LogInformation("Step-up required for {Method} {Route}: {Reason}.",
                    context.Request.Method, endpoint.RoutePattern.RawText, result);
                var options = evaluator.Options;
                context.Response.Headers[HeaderNames.WWWAuthenticate] =
                    "Bearer error=\"insufficient_user_authentication\", " +
                    "error_description=\"A recent second-factor sign-in is required\", " +
                    $"acr_values=\"{options.AcceptedAcrValues[0]}\", max_age=\"{options.MaxAgeSeconds}\"";
                await Results.Problem(
                    title: "Step-up authentication required",
                    detail: StepUpEvaluator.Describe(result),
                    statusCode: StatusCodes.Status401Unauthorized).ExecuteAsync(context);
                return;
            }
        }

        await next(context);
    }
}

/// <summary>Pipeline registration for <see cref="StepUpMiddleware"/>.</summary>
public static class StepUpApplicationBuilderExtensions
{
    /// <summary>Adds the step-up check. Call it right after <c>UseAuthorization()</c>.</summary>
    public static IApplicationBuilder UseQertumStepUp(this IApplicationBuilder app) => app.UseMiddleware<StepUpMiddleware>();
}
