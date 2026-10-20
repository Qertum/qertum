using System.Globalization;
using Microsoft.AspNetCore.Http;

namespace Qertum.Services;

/// <summary>
/// The polling hint for a request that is on its way to a final state: <c>Retry-After</c> on the approve and
/// revoke responses and on every read of the request while it is in progress
/// (<see cref="CertificateRequestStatusExtensions.IsInProgress"/>), and nothing once it is final or while it
/// waits for a person. Status codes and bodies are unchanged. A constant, not configuration: it has one right
/// value for the queue consumer's wake-up latency. A new endpoint that returns a request in an in-progress
/// status calls <see cref="Apply"/> too.
/// </summary>
public static class ProgressHints
{
    /// <summary>Seconds a client should wait before asking again.</summary>
    public const int RetryAfterSeconds = 2;

    /// <summary>Sets <c>Retry-After</c> when <paramref name="status"/> is in progress.</summary>
    public static void Apply(HttpResponse response, CertificateRequestStatus status)
    {
        if (status.IsInProgress())
            response.Headers.RetryAfter = RetryAfterSeconds.ToString(CultureInfo.InvariantCulture);
    }
}
