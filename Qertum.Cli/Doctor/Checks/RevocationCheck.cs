using System.Net;
using System.Text.Json;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// The CRL is fetched without a token (from the configured distribution point when the caller may read the
/// setting, otherwise <c>{api}/crl</c>), must not have expired, and warns when under a quarter of its window
/// is left. Its signature is verified against the root or issuer certificate the trust check collected;
/// without one the output says "signature not verified". Not delta CRLs, OCSP or one certificate's status.
/// </summary>
internal sealed class RevocationCheck : IDoctorCheck
{
    private const int MaxCrlBytes = 10 << 20;
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public string Id => "revocation";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        var findings = new List<(DoctorStatus Status, string Text)>();
        var notVerified = new List<string> { "the delta CRL, OCSP, and whether a particular certificate is listed" };
        Uri? crlUri = null;

        if (context.Shared.SessionAccepted && context.Token is not null && context.ApiUrl is not null)
        {
            var settingsUri = DoctorUrls.Combine(context.ApiUrl, "/v1/settings");
            var settingsResponse = await DoctorHttp.GetAsync(context, settingsUri, context.Token, 1 << 20, ct);
            if (settingsResponse.Ok && settingsResponse.Status == HttpStatusCode.OK && ReadSettings(settingsResponse.Body) is { } settings)
            {
                if (string.IsNullOrWhiteSpace(settings.CrlDistributionPoint))
                    findings.Add((DoctorStatus.Warn, "no CRL distribution point is configured: certificates are issued without one, so clients cannot find the CRL"));
                else if (DoctorUrls.TryHttp(settings.CrlDistributionPoint, out var configured))
                    crlUri = configured;
            }
            else
            {
                notVerified.Add("the CRL distribution point setting (needs settings.edit)");
            }
        }

        if (crlUri is null && context.ApiUrl is not null)
            crlUri = DoctorUrls.Combine(context.ApiUrl, "/crl");
        if (crlUri is null)
            return DoctorResult.Skip(Id, "no API URL and no CRL distribution point are known");

        var response = await DoctorHttp.GetAsync(context, crlUri, bearerToken: null, MaxCrlBytes, ct);
        if (!response.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(response, crlUri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, notVerified: notVerified, hint: hint);
        }

        if (response.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the CRL at {crlUri} answered {(int)response.Status!.Value}", notVerified: notVerified);

        X509Crl? crl;
        try
        {
            crl = new X509CrlParser().ReadCrl(response.Body);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            crl = null;
        }

        if (crl is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the response from {crlUri} is not a CRL", notVerified: notVerified,
                hint: "is the distribution point URL right?");

        var verified = new List<string> { $"a CRL was fetched from {crlUri.Host} without a login" };
        var now = context.NowUtc;
        if (crl.NextUpdate is null)
        {
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the CRL has no nextUpdate, so clients cannot tell when it goes stale",
                verified: verified, notVerified: notVerified);
        }

        var nextUpdate = crl.NextUpdate.Value;
        if (now > nextUpdate)
        {
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"the CRL expired on {nextUpdate:yyyy-MM-dd HH:mm} UTC",
                verified: verified, notVerified: notVerified, hint: "the CA must publish a new CRL; check the queue consumer's CRL refresh job");
        }

        var window = nextUpdate - crl.ThisUpdate;
        var remaining = nextUpdate - now;
        verified.Add($"nextUpdate is {nextUpdate:yyyy-MM-dd HH:mm} UTC, in the future");
        if (window > TimeSpan.Zero && remaining.TotalSeconds < window.TotalSeconds * 0.25)
            findings.Add((DoctorStatus.Warn, $"the CRL has under 25% of its validity left ({remaining.TotalHours:0.#} h of {window.TotalHours:0.#} h)"));

        var candidates = context.Shared.Roots.Concat(context.Shared.IssuerCertificates).Where(c => c.SubjectDN.Equivalent(crl.IssuerDN)).ToList();
        if (candidates.Count == 0)
        {
            notVerified.Add("signature not verified: the issuer certificate was not available (the trust check did not run or failed)");
        }
        else if (candidates.Any(c => SignedBy(crl, c)))
        {
            verified.Add("its signature verifies against the issuer certificate");
        }
        else
        {
            return DoctorResult.Of(Id, DoctorStatus.Fail, "the CRL signature does not verify against the issuer certificate",
                verified: verified, notVerified: notVerified, hint: "this CRL was not signed by the issuer it names");
        }

        // Each non-legacy issuer publishes its own CRL at {distribution point}/{issuerId}; only one URL is probed.
        if (context.Shared.Issuers is null)
            notVerified.Add("the CRLs of issuers other than the one served at this URL (the issuer list needs a login)");
        else if (context.Shared.Issuers.Count(i => i.Status is IssuerStatus.Active or IssuerStatus.Retired) is var inUse and > 1)
            notVerified.Add($"the CRLs of the other {inUse - 1} issuer(s) in use; each publishes its own at {crlUri}/<issuerId>");

        var worst = findings.Count == 0 ? DoctorStatus.Pass : DoctorStatus.Warn;
        return DoctorResult.Of(Id, worst,
            worst == DoctorStatus.Pass ? $"the CRL at {crlUri.Host} is fresh" : "the CRL or its configuration needs attention",
            verified: verified, notVerified: notVerified, findings: findings.Select(f => f.Text),
            hint: worst == DoctorStatus.Pass ? null : "see Settings → Revocation");
    }

    private static bool SignedBy(X509Crl crl, X509Certificate issuer)
    {
        try
        {
            crl.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(issuer)));
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return false;
        }
    }

    private static CaSettings? ReadSettings(byte[] body)
    {
        try
        {
            return JsonSerializer.Deserialize<CaSettings>(body, Web);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
