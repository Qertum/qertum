using System.Net;
using System.Text.Json;
using Qertum.Services;

namespace Qertum.Cli.Doctor.Checks;

/// <summary>
/// Relays the server's own attention report (CA and issuer expiry, delta CRL base, failed issuance and
/// webhooks, recovery status). A warning is Warn, a critical is Fail. Kinds that failed server-side are
/// unknown, never OK; kinds the caller's role withholds are listed as not checked.
/// </summary>
internal sealed class ServerReportsCheck : IDoctorCheck
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public string Id => "server-reports";

    public async Task<DoctorResult> RunAsync(DoctorContext context, CancellationToken ct)
    {
        if (!context.Shared.SessionAccepted || context.Token is null || context.ApiUrl is null)
            return DoctorResult.Skip(Id, "needs the session check to pass");

        var uri = DoctorUrls.Combine(context.ApiUrl, "/v1/dashboard/attention");
        var response = await DoctorHttp.GetAsync(context, uri, context.Token, 1 << 20, ct);
        if (!response.Ok)
        {
            var (summary, hint) = DoctorHttp.Explain(response, uri, context.Timeout);
            return DoctorResult.Of(Id, DoctorStatus.Fail, summary, hint: hint);
        }

        if (response.Status != HttpStatusCode.OK)
            return DoctorResult.Of(Id, DoctorStatus.Fail, $"GET /v1/dashboard/attention answered {(int)response.Status!.Value}");

        AttentionReport? report;
        try
        {
            report = JsonSerializer.Deserialize<AttentionReport>(response.Body, Web);
        }
        catch (JsonException)
        {
            report = null;
        }

        if (report is null)
            return DoctorResult.Of(Id, DoctorStatus.Fail, "GET /v1/dashboard/attention answered something that is not an attention report");

        var findings = report.Items
            .Select(i => $"{(i.Severity == AttentionSeverity.Critical ? "critical" : "warning")}: {i.Title}")
            .ToList();
        findings.AddRange(report.UnavailableKinds.Select(k => $"{k}: the server could not check this, so its state is unknown"));

        var notVerified = new List<string> { "anything beyond what your role may see on the server" };
        if (report.WithheldKinds.Count > 0)
            notVerified.Add($"not checked, your role lacks the permission: {string.Join(", ", report.WithheldKinds)}");

        var status = report.Items.Any(i => i.Severity == AttentionSeverity.Critical) ? DoctorStatus.Fail
            : report.Items.Count > 0 || report.UnavailableKinds.Count > 0 ? DoctorStatus.Warn
            : DoctorStatus.Pass;

        return DoctorResult.Of(Id, status,
            status switch
            {
                DoctorStatus.Fail => "the server reports a critical problem",
                DoctorStatus.Warn => "the server reports something that needs attention",
                _ => "the server reports nothing that needs attention"
            },
            verified: ["the server ran its own checks and returned its attention report"],
            notVerified: notVerified, findings: findings,
            hint: status == DoctorStatus.Pass ? null : "open the dashboard's Attention required list for the evidence and the next step");
    }
}
