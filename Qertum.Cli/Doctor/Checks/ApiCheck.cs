using System.Net;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// An unauthenticated <c>GET /v1/me/access</c> must answer 401: the API is up, its TLS certificate is
/// accepted by this machine, and authentication is enforced. Sends no token.
/// </summary>
internal sealed class ApiCheck : IDoctorCheck
{
    public string Id => "api";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (context.ApiUrl is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "no API URL is known",
                notVerified: ["everything that needs the API"],
                hint: "pass --api-url, set QERTUM_API_URL, or run 'qca auth login'");
        if (!DoctorUrls.TryHttp(context.ApiUrl, out _))
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the API URL '{context.ApiUrl}' is not an http(s) URL",
                notVerified: ["everything that needs the API"], hint: "use a URL such as https://ca.example.org");

        var uri = DoctorUrls.Combine(context.ApiUrl, "/v1/me/access");
        var response = await DoctorHttp.GetAsync(context, uri, bearerToken: null, 1 << 20, ct);
        if (!response.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(response, uri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, notVerified: ["everything that needs the API"], hint: hint);
        }

        if (response.Status == HttpStatusCode.Unauthorized)
        {
            context.Shared.ApiReachable = true;
            var secure = uri.Scheme == "https";
            return DoctorResult.Of(Id, DoctorStatus.Pass, $"API reachable at {uri.GetLeftPart(UriPartial.Authority)}",
                verified: secure
                    ? [$"the API answers at {uri.Host}", "its TLS certificate chain and host name are accepted by this machine", "authentication is enforced (401 without a token)"]
                    : [$"the API answers at {uri.Host}", "authentication is enforced (401 without a token)"],
                notVerified: secure ? ["that the API's data is healthy"] : ["TLS: the URL is plain http", "that the API's data is healthy"]);
        }

        if (response.Status == HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "authentication is not enforced: GET /v1/me/access answered 200 without a token",
                hint: "this does not behave like a configured Qertum API; check --api-url and the identity setup");

        var code = (int)response.Status!.Value;
        var redirect = response.Location is { } location ? $" It redirects to {location}: use that URL as --api-url." : "";
        return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/me/access answered {code}, expected 401 without a token",
            notVerified: ["everything that needs the API"],
            hint: $"is --api-url the API and not the web UI?{redirect}");
    }
}
