using System.Text;

namespace Qertum.Cli.Doctor;

/// <summary>The two output forms: a text block per check, and camelCase-ready JSON.</summary>
internal static class DoctorRenderer
{
    public static string Table(DoctorReport report)
    {
        var text = new StringBuilder();
        foreach (var result in report.Results)
        {
            text.AppendLine($"{Label(result.Status),-5} {result.Id,-15} {result.Summary}");
            if (result.Status == DoctorStatus.Skipped)
                continue;
            foreach (var finding in result.Findings)
                text.AppendLine($"        - {finding}");
            if (result.Verified.Count > 0)
                text.AppendLine($"        verified:     {string.Join("; ", result.Verified)}");
            if (result.NotVerified.Count > 0)
                text.AppendLine($"        not verified: {string.Join("; ", result.NotVerified)}");
            if (result.Hint is not null)
                text.AppendLine($"        hint:         {result.Hint}");
        }

        text.AppendLine($"Summary: {report.Passed} passed, {report.Warnings} warning(s), {report.Failed} failed, {report.Skipped} skipped");
        return text.ToString();
    }

    public static object Json(DoctorReport report) => new
    {
        checks = report.Results.Select(r => new
        {
            id = r.Id,
            status = r.Status.ToString().ToLowerInvariant(),
            summary = r.Summary,
            verified = r.Verified,
            notVerified = r.NotVerified,
            findings = r.Findings,
            hint = r.Hint,
            reason = r.Reason
        }).ToList(),
        summary = new { passed = report.Passed, warnings = report.Warnings, failed = report.Failed, skipped = report.Skipped },
        exitCode = report.ExitCode
    };

    private static string Label(DoctorStatus status) => status switch
    {
        DoctorStatus.Pass => "PASS",
        DoctorStatus.Warn => "WARN",
        DoctorStatus.Fail => "FAIL",
        _ => "SKIP"
    };
}
