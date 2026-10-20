using System.Net;

namespace Qertum.Services.Webhooks;

/// <summary>A parsed webhook target with a canonical host and effective port.</summary>
public sealed record WebhookDestinationTarget(Uri Uri, string Scheme, string Host, int Port)
{
    /// <summary>Parses a complete HTTP(S) URL and rejects ambiguous or unsafe URL forms.</summary>
    public static bool TryParse(string? raw, out WebhookDestinationTarget? target, out string? error)
    {
        target = null;
        error = "Url must be an absolute http or https URL without credentials or a fragment.";
        if (string.IsNullOrWhiteSpace(raw) || raw != raw.Trim() || raw.Contains('\\')) return false;

        var schemeEnd = raw.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0) return false;
        var authorityStart = schemeEnd + 3;
        var authorityEnd = raw.IndexOfAny(['/', '?', '#'], authorityStart);
        if (authorityEnd < 0) authorityEnd = raw.Length;
        var authority = raw[authorityStart..authorityEnd];
        if (authority.Length == 0 || authority.Contains('@') || authority.Contains('{') ||
            authority.Contains('}') || authority.Contains('%') || raw.Contains('#')) return false;

        if (!System.Uri.TryCreate(raw, UriKind.Absolute, out var uri) ||
            (uri.Scheme != System.Uri.UriSchemeHttp && uri.Scheme != System.Uri.UriSchemeHttps) ||
            string.IsNullOrEmpty(uri.Host) || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Fragment) || uri.Port is < 1 or > 65535)
            return false;

        var host = uri.IdnHost.TrimEnd('.').ToLowerInvariant();
        if (host.Length == 0) return false;
        if (IPAddress.TryParse(host, out var address))
            host = address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();

        target = new WebhookDestinationTarget(uri, uri.Scheme, host, uri.Port);
        error = null;
        return true;
    }
}
