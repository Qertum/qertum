using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Qertum.Services;

namespace Qertum.Web.Auth;

/// <summary>Outcome of reading the caller's access, with the same three-way split as the token client.</summary>
/// <param name="Outcome">Whether the call succeeded, was refused, or could not be made.</param>
/// <param name="Access">The answer, when the call succeeded.</param>
public sealed record MeAccessResult(OidcCallOutcome Outcome, MyAccessResponse? Access);

/// <summary>Reads the caller's access. Seam so circuit revalidation can be tested without HTTP.</summary>
public interface IMeAccess
{
    /// <summary>Reads the caller's access with the given bearer token.</summary>
    Task<MeAccessResult> GetAsync(string accessToken, CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads <c>GET /v1/me/access</c> with an explicit bearer token. Separate from the typed API client
/// because it runs inside the cookie handler and in circuit revalidation, where the token to use is
/// the one just refreshed rather than whatever the ambient handler would attach.
/// </summary>
public sealed class MeAccessClient(IHttpClientFactory httpClientFactory, ILogger<MeAccessClient> logger) : IMeAccess
{
    /// <summary>Name of the plain HTTP client used for these calls.</summary>
    public const string HttpClientName = "me-access";

    /// <inheritdoc />
    public async Task<MeAccessResult> GetAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        var client = httpClientFactory.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/me/access");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        try
        {
            using var response = await client.SendAsync(request, cancellationToken);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                return new MeAccessResult(OidcCallOutcome.Rejected, null);
            if (!response.IsSuccessStatusCode)
                return new MeAccessResult(OidcCallOutcome.Unavailable, null);

            var access = await response.Content.ReadFromJsonAsync<MyAccessResponse>(cancellationToken);
            return access is null
                ? new MeAccessResult(OidcCallOutcome.Unavailable, null)
                : new MeAccessResult(OidcCallOutcome.Success, access);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not read the caller's access; keeping the current permissions.");
            return new MeAccessResult(OidcCallOutcome.Unavailable, null);
        }
    }
}
