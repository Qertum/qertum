using System.Net;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// From <c>/v1/enrollment/options</c> (the one request that carries the token): the ACME directory answers
/// with the endpoints a client needs, and the EST <c>cacerts</c> answers 200 or 401 (up, authentication
/// enforced). The probes carry no token. Reachability only: not an enrollment, not credentials.
/// </summary>
internal sealed class EnrollmentCheck : IDoctorCheck
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public string Id => "enrollment";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (!context.Shared.SessionAccepted || context.Token is null || context.ApiUrl is null)
            return DoctorResult.Skip(Id, "needs the session check to pass");

        var optionsUri = DoctorUrls.Combine(context.ApiUrl, "/v1/enrollment/options");
        var optionsResponse = await DoctorHttp.GetAsync(context, optionsUri, context.Token, 1 << 20, ct);
        if (!optionsResponse.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(optionsResponse, optionsUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (optionsResponse.Status == HttpStatusCode.Forbidden)
            return DoctorResult.Skip(Id, "needs certificates.create to read the enrollment options");
        if (optionsResponse.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/enrollment/options answered {(int)optionsResponse.Status!.Value}");

        EnrollmentOptionsResponse? options;
        try
        {
            options = JsonSerializer.Deserialize<EnrollmentOptionsResponse>(optionsResponse.Body, Web);
        }
        catch (JsonException)
        {
            options = null;
        }

        if (options is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "GET /v1/enrollment/options answered something that is not an options document");
        if (options.Acme is null && options.Est is null)
            return DoctorResult.Skip(Id, "no ACME or EST route is configured (no public directory or EST URL)");

        var verified = new List<string>();
        var findings = new List<string>();
        if (options.Acme is { } acme)
            await CheckAcmeAsync(context, acme.DirectoryUrl, verified, findings, ct);
        if (options.Est is { } est)
            await CheckEstAsync(context, est.BaseUrl, verified, findings, ct);

        var notVerified = new List<string> { "that an enrollment would succeed", "credentials, account keys and external account binding" };
        return findings.Count == 0
            ? DoctorResult.Of(Id, DoctorStatus.Pass, "the configured enrollment endpoints are reachable from this machine", verified: verified, notVerified: notVerified)
            : DoctorResult.Of(Id, DoctorStatus.Fail, "an enrollment endpoint is not usable from this machine",
                verified: verified, notVerified: notVerified, findings: findings, hint: "fix the URL or network path; clients on this network will fail the same way");
    }

    private static async Task CheckAcmeAsync(DoctorContext context, string directoryUrl, List<string> verified, List<string> findings, CancellationToken ct)
    {
        if (!DoctorUrls.TryHttp(directoryUrl, out var uri))
        {
            findings.Add($"ACME: the directory URL '{directoryUrl}' is not an http(s) URL");
            return;
        }

        var response = await DoctorHttp.GetAsync(context, uri, bearerToken: null, 1 << 20, ct);
        if (!response.Ok)
        {
            findings.Add("ACME: " + DoctorHttp.Explain(response, uri, context.Timeout).Summary);
            return;
        }

        var missing = new List<string>();
        try
        {
            using var document = JsonDocument.Parse(response.Body);
            foreach (var name in new[] { "newNonce", "newAccount", "newOrder" })
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty(name, out var value)
                    || value.ValueKind != JsonValueKind.String)
                    missing.Add(name);
            }
        }
        catch (JsonException)
        {
            missing.AddRange(["newNonce", "newAccount", "newOrder"]);
        }

        if (response.Status != HttpStatusCode.OK)
            findings.Add($"ACME: the directory at {uri.Host} answered {(int)response.Status!.Value}");
        else if (missing.Count > 0)
            findings.Add($"ACME: the directory is missing {string.Join(", ", missing)}");
        else
            verified.Add($"ACME directory at {uri.Host} answers and lists newNonce, newAccount and newOrder");
    }

    private static async Task CheckEstAsync(DoctorContext context, string baseUrl, List<string> verified, List<string> findings, CancellationToken ct)
    {
        if (!DoctorUrls.TryHttp(baseUrl, out _))
        {
            findings.Add($"EST: the base URL '{baseUrl}' is not an http(s) URL");
            return;
        }

        var uri = DoctorUrls.Combine(baseUrl, "/cacerts");
        var response = await DoctorHttp.GetAsync(context, uri, bearerToken: null, 1 << 20, ct);
        if (!response.Ok)
        {
            findings.Add("EST: " + DoctorHttp.Explain(response, uri, context.Timeout).Summary);
            return;
        }

        if (response.Status is HttpStatusCode.OK or HttpStatusCode.Unauthorized)
            verified.Add($"EST at {uri.Host} is up and its cacerts answered {(int)response.Status!.Value} (authentication is enforced when 401)");
        else
            findings.Add($"EST: cacerts at {uri.Host} answered {(int)response.Status!.Value}");
    }
}
