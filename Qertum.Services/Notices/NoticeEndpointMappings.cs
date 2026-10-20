using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;

namespace Qertum.Services.Notices;

/// <summary>REST surface of expiry and renewal notices under <c>/v1/notices</c>.</summary>
public static class NoticeEndpointMappings
{
    /// <summary>Maps <c>GET /v1/notices</c> (<c>certificates.view</c>).</summary>
    /// <param name="v1">The <c>/v1</c> group.</param>
    /// <returns>The same group.</returns>
    public static RouteGroupBuilder MapNoticeApi(this RouteGroupBuilder v1)
    {
        v1.MapGet("/notices", async (
            [FromQuery] string? status, [FromQuery] string? kind, [FromQuery] int? page, [FromQuery] int? pageSize,
            INoticeQueryService notices, CancellationToken cancellationToken) =>
        {
            NoticeStatus? wantedStatus = null;
            if (!string.IsNullOrWhiteSpace(status))
            {
                if (!Enum.TryParse<NoticeStatus>(status, ignoreCase: true, out var parsed) || !Enum.IsDefined(parsed))
                    return ApiProblem.BadRequest($"Unknown status '{status}'. Use Open or Resolved.");
                wantedStatus = parsed;
            }

            NoticeKind? wantedKind = null;
            if (!string.IsNullOrWhiteSpace(kind))
            {
                if (!Enum.TryParse<NoticeKind>(kind, ignoreCase: true, out var parsed) || !Enum.IsDefined(parsed))
                    return ApiProblem.BadRequest($"Unknown kind '{kind}'. Use Expiring, RenewalStalled or RenewalFailed.");
                wantedKind = parsed;
            }

            return Results.Ok(await notices.ListAsync(
                wantedStatus, wantedKind, Math.Clamp(page ?? 1, 1, 100_000), Math.Clamp(pageSize ?? 50, 1, 200), cancellationToken));
        }).WithTags("Notices").RequireAuthorization(AppPermissions.CertificatesView).RequireRateLimiting("api");

        return v1;
    }
}
