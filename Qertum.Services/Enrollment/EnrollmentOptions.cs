using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Enrollment;

/// <summary>
/// Public enrollment URLs shown to requesters in the request wizard. Display only: nothing
/// authenticates against them, and a deployment behind a reverse proxy sets its public URLs here.
/// </summary>
public sealed class EnrollmentOptions
{
    public const string SectionName = "Enrollment";

    /// <summary>Public ACME directory URL.</summary>
    public string? AcmeDirectoryUrl { get; set; }

    /// <summary>Public EST base URL (<c>…/.well-known/est</c>).</summary>
    public string? EstBaseUrl { get; set; }
}

/// <summary>
/// The configured URLs after validation. A value that is not an absolute http(s) URI is treated as
/// unset, so the wizard never renders a broken link; a non-blank invalid value is logged once, when
/// ApiService resolves this at startup.
/// </summary>
public sealed class EnrollmentDisplayUrls
{
    public EnrollmentDisplayUrls(IOptions<EnrollmentOptions> options, ILogger<EnrollmentDisplayUrls> logger)
    {
        AcmeDirectoryUrl = Normalize(options.Value.AcmeDirectoryUrl, "Enrollment:AcmeDirectoryUrl", logger);
        EstBaseUrl = Normalize(options.Value.EstBaseUrl, "Enrollment:EstBaseUrl", logger);
    }

    public string? AcmeDirectoryUrl { get; }

    public string? EstBaseUrl { get; }

    private static string? Normalize(string? value, string key, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var trimmed = value.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
            (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            return trimmed.TrimEnd('/');

        logger.LogWarning("{Key} is not an absolute http(s) URL and is ignored; the enrollment wizard will not offer that route.", key);
        return null;
    }
}
