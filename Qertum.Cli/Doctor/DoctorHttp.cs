using System.Net;
using System.Net.Http.Headers;
using System.Security.Authentication;
using System.Text;

namespace Qertum.Cli.Doctor;

/// <summary>URL helpers. A path prefix in the base URL is kept.</summary>
internal static class DoctorUrls
{
    public static bool TryHttp(string? value, out Uri uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var parsed) && parsed.Scheme is "http" or "https")
        {
            uri = parsed;
            return true;
        }

        uri = null!;
        return false;
    }

    /// <summary><c>Combine("https://h/qertum/", "/v1/x")</c> is <c>https://h/qertum/v1/x</c>.</summary>
    public static Uri Combine(string baseUrl, string path) => new(baseUrl.TrimEnd('/') + path);
}

internal enum DoctorFailureKind { None, NameResolution, ConnectionRefused, Tls, Timeout, TooLarge, Other }

/// <summary>An HTTP answer, or the reason there was none. A redirect is an answer, carrying its Location.</summary>
internal sealed record DoctorResponse(HttpStatusCode? Status, byte[] Body, string? Location, DoctorFailureKind Failure, string? FailureDetail)
{
    public bool Ok => Failure == DoctorFailureKind.None;

    public string Text => Encoding.UTF8.GetString(Body);
}

/// <summary>
/// One GET with a timeout, a body cap and no redirect following. The bearer token goes only where the
/// caller passes one. Transport failures are classified so a check can say why, not just that it failed.
/// </summary>
internal static class DoctorHttp
{
    public static async Task<DoctorResponse> GetAsync(DoctorContext context, Uri uri, string? bearerToken, int maxBytes, CancellationToken ct)
    {
        using var http = new HttpClient(context.Handler, disposeHandler: false);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        if (bearerToken is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(context.Timeout);
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            var location = response.Headers.Location?.ToString();
            var body = await ReadCappedAsync(response.Content, maxBytes, timeout.Token);
            return body is null
                ? new DoctorResponse(response.StatusCode, [], location, DoctorFailureKind.TooLarge, $"the body is larger than {maxBytes} bytes")
                : new DoctorResponse(response.StatusCode, body, location, DoctorFailureKind.None, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DoctorResponse(null, [], null, DoctorFailureKind.Timeout, $"no answer within {context.Timeout.TotalSeconds:0.#} s");
        }
        catch (HttpRequestException ex)
        {
            return new DoctorResponse(null, [], null, Classify(ex), ex.Message);
        }
    }

    private static async Task<byte[]?> ReadCappedAsync(HttpContent content, int maxBytes, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > maxBytes)
                return null;
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static DoctorFailureKind Classify(HttpRequestException ex)
    {
        if (ex.HttpRequestError == HttpRequestError.SecureConnectionError || HasInner<AuthenticationException>(ex))
            return DoctorFailureKind.Tls;
        return ex.HttpRequestError switch
        {
            HttpRequestError.NameResolutionError => DoctorFailureKind.NameResolution,
            HttpRequestError.ConnectionError => DoctorFailureKind.ConnectionRefused,
            _ => DoctorFailureKind.Other
        };
    }

    private static bool HasInner<T>(Exception ex)
    {
        for (var inner = ex.InnerException; inner is not null; inner = inner.InnerException)
            if (inner is T) return true;
        return false;
    }

    /// <summary>A one-line reason and a next step for a probe that got no usable answer.</summary>
    public static (string Summary, string Hint) Explain(DoctorResponse response, Uri uri, TimeSpan timeout)
    {
        var host = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        return response.Failure switch
        {
            DoctorFailureKind.NameResolution =>
                ($"cannot resolve the host name {host}", "check the URL for typos and that your DNS knows the name"),
            DoctorFailureKind.ConnectionRefused =>
                ($"cannot connect to {host} (connection refused or unreachable)", "is the service running, and is the port open from this machine?"),
            DoctorFailureKind.Tls =>
                ($"the TLS handshake with {host} failed: this machine does not trust the server certificate, or the host name does not match it",
                    "install the CA root on this machine (see the trust check) or use the host name on the certificate"),
            DoctorFailureKind.Timeout =>
                ($"no answer from {host} within {timeout.TotalSeconds:0.#} s", "raise --timeout, or check the network path and any firewall"),
            DoctorFailureKind.TooLarge =>
                ($"the answer from {host} is larger than doctor reads ({response.FailureDetail})", "this does not look like the expected endpoint"),
            _ => ($"the call to {host} failed: {response.FailureDetail}", "check the URL and that the service is reachable")
        };
    }
}
