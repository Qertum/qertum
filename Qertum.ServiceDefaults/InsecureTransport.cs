using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Qertum.ServiceDefaults;

/// <summary>
/// The warning every host that users reach in a browser or with a token logs when its public address is plain
/// <c>http</c>: sign-in, access tokens and the administrator password then cross the network unencrypted.
/// </summary>
public static class InsecureTransport
{
    /// <summary>
    /// Logs a warning when <paramref name="publicUrl"/> is an <c>http</c> address and the host is not running in
    /// Development (the local stack is plain http by design). Returns true when it warned. A missing or relative
    /// value is not this check's business: option validation already rejects it.
    /// </summary>
    /// <param name="logger">Receives the warning.</param>
    /// <param name="environment">The host environment; Development never warns.</param>
    /// <param name="service">Which service is configured, for the message (for example "ApiService").</param>
    /// <param name="publicUrl">The browser- or client-facing address of the identity authority.</param>
    public static bool WarnIfPlainHttp(ILogger logger, IHostEnvironment environment, string service, string? publicUrl)
    {
        if (environment.IsDevelopment()) return false;
        if (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp) return false;

        logger.LogWarning(
            "{Service} is configured for plain http ({PublicUrl}): sign-in, access tokens and the administrator password " +
            "cross the network unencrypted. Use it only on a trusted network; otherwise serve web, identity and API over " +
            "https behind a TLS-terminating proxy (QERTUM_PUBLIC_SCHEME=https, or QERTUM_SCHEME=https for the multi-container layout).",
            service, publicUrl);
        return true;
    }
}
