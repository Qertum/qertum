using System.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace Qertum.Services;

/// <summary>
/// The id an API caller can quote to find a request in the server's console log: the request's trace id in
/// its bare 32-hex form, which is what every log line prints (<c>Qertum.ServiceDefaults</c>). It is sent
/// as the <see cref="HeaderName"/> header on every ApiService response and repeated as <c>traceId</c> in an
/// error body. It is random and carries nothing about the caller.
/// </summary>
public static class CorrelationIds
{
    /// <summary>Response header carrying the id.</summary>
    public const string HeaderName = "X-Correlation-Id";

    /// <summary>
    /// The request's trace id; when no activity exists (no tracing listener) ASP.NET's own request id, which
    /// is what the framework's log scope prints instead.
    /// </summary>
    public static string For(HttpContext context) =>
        Activity.Current is { } activity && activity.TraceId != default
            ? activity.TraceId.ToString()
            : context.TraceIdentifier;
}
