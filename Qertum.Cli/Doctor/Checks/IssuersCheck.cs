using System.Net;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// The CA is initialized, an issuer is the default, and no issuer still in use has ended or ends within
/// 90 days. The issuer list needs <c>certificates.view</c>; without it the CA status alone is checked and
/// the list is reported as not verified.
/// </summary>
internal sealed class IssuersCheck : IDoctorCheck
{
    private const int WarnDays = 90;
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public string Id => "issuers";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (!context.Shared.SessionAccepted || context.ApiUrl is null || context.Token is null)
            return DoctorResult.Skip(Id, "needs the session check to pass");

        var statusUri = DoctorUrls.Combine(context.ApiUrl, "/v1/ca/status");
        var statusResponse = await DoctorHttp.GetAsync(context, statusUri, context.Token, 1 << 20, ct);
        if (!statusResponse.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(statusResponse, statusUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (statusResponse.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/ca/status answered {(int)statusResponse.Status!.Value}");

        var status = Parse<CaStatusResponse>(statusResponse.Body);
        if (status is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "GET /v1/ca/status answered something that is not a CA status");
        if (!status.IsInitialized)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the CA is not initialized",
                notVerified: ["issuers, trust and revocation, which need a CA"], hint: "finish CA onboarding in the Web UI first");

        var verified = new List<string> { "the CA is initialized" };
        var notVerified = new List<string> { "anything about the key material" };
        var findings = new List<(DoctorStatus Status, string Text)>();
        if (status.ExplicitCurveParameters)
            findings.Add((DoctorStatus.Warn, "the CA certificate has explicit EC parameters: some clients reject chains under it"));

        var listUri = DoctorUrls.Combine(context.ApiUrl, "/v1/issuers");
        var listResponse = await DoctorHttp.GetAsync(context, listUri, context.Token, 1 << 20, ct);
        if (!listResponse.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(listResponse, listUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (listResponse.Status == HttpStatusCode.Forbidden)
        {
            notVerified.Add("the issuer list and expiry dates (needs certificates.view)");
        }
        else if (listResponse.Status != HttpStatusCode.OK)
        {
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/issuers answered {(int)listResponse.Status!.Value}");
        }
        else
        {
            var issuers = Parse<List<IssuerResponse>>(listResponse.Body);
            if (issuers is null)
                return DoctorResult.Of(Id, DoctorStatus.Fail, "GET /v1/issuers answered something that is not an issuer list");

            context.Shared.Issuers = issuers;
            var inUse = issuers.Where(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired).ToList();
            var defaultIssuer = issuers.FirstOrDefault(i => i.IsDefault);
            if (defaultIssuer is null)
                return DoctorResult.Of(Id, DoctorStatus.Fail, "no default issuer: new certificates cannot be signed",
                    verified: verified, hint: "make an Active online issuer the default: qca issuers make-default <id>");

            verified.Add($"the default issuer is '{defaultIssuer.Name}'");
            verified.Add($"{inUse.Count} issuer(s) in use were checked against their certificate dates");
            var now = context.NowUtc;
            foreach (var issuer in inUse.Where(i => i.ValidTo is not null))
            {
                var ends = issuer.ValidTo!.Value;
                if (ends < now)
                    findings.Add((DoctorStatus.Fail, $"issuer '{issuer.Name}' ended on {ends:yyyy-MM-dd}"));
                else if (ends < now.AddDays(WarnDays))
                    findings.Add((DoctorStatus.Warn, $"issuer '{issuer.Name}' ends on {ends:yyyy-MM-dd} (in {(int)(ends - now).TotalDays} days)"));
            }
        }

        var worst = findings.Count == 0 ? DoctorStatus.Pass : findings.Max(f => f.Status) == DoctorStatus.Fail ? DoctorStatus.Fail : DoctorStatus.Warn;
        var text = findings.Select(f => f.Text).ToList();
        return DoctorResult.Of(Id, worst,
            worst switch
            {
                DoctorStatus.Fail => "an issuer has ended",
                DoctorStatus.Warn => "an issuer needs attention soon",
                _ => "the CA is initialized and its issuers are in order"
            },
            verified: verified, notVerified: notVerified, findings: text,
            hint: worst == DoctorStatus.Pass ? null : "roll the issuer over before it ends (see the issuer commands under 'qca issuers')");
    }

    private static T? Parse<T>(byte[] body) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(body, Web);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
