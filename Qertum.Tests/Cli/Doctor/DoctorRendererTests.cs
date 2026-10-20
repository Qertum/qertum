using System.Text.Json;
using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class DoctorRendererTests
{
    private static DoctorReport Report() => new(
    [
        DoctorResult.Of("api", DoctorStatus.Pass, "API reachable", verified: ["it answers 401", "TLS accepted"], notVerified: ["data health"]),
        DoctorResult.Of("trust", DoctorStatus.Warn, "root not installed", verified: ["roots verify"], findings: ["root 'A' is not installed"], hint: "install it"),
        DoctorResult.Skip("session", "not logged in")
    ]);

    [Fact]
    public void Table_ShowsStatusIdAndSummary_ThenVerifiedAndNotVerified()
    {
        var text = DoctorRenderer.Table(Report());

        Assert.Contains("PASS  api", text, StringComparison.Ordinal);
        Assert.Contains("verified:     it answers 401; TLS accepted", text, StringComparison.Ordinal);
        Assert.Contains("not verified: data health", text, StringComparison.Ordinal);
        Assert.Contains("- root 'A' is not installed", text, StringComparison.Ordinal);
        Assert.Contains("hint:         install it", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ASkippedCheck_ShowsOnlyItsReason()
    {
        var lines = DoctorRenderer.Table(Report()).Split('\n');

        var skip = Array.FindIndex(lines, l => l.StartsWith("SKIP", StringComparison.Ordinal));
        Assert.Contains("not logged in", lines[skip], StringComparison.Ordinal);
        Assert.DoesNotContain("verified:", lines[skip + 1], StringComparison.Ordinal);
    }

    [Fact]
    public void TheSummaryLine_CountsEveryStatus() =>
        Assert.Contains("Summary: 1 passed, 1 warning(s), 0 failed, 1 skipped", DoctorRenderer.Table(Report()), StringComparison.Ordinal);

    [Fact]
    public void Json_HasStableIds_LowerCaseStatuses_AndTheExitCode()
    {
        var json = JsonSerializer.Serialize(DoctorRenderer.Json(Report()), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        var checks = root.GetProperty("checks");
        Assert.Equal(["api", "trust", "session"], checks.EnumerateArray().Select(c => c.GetProperty("id").GetString()));
        Assert.Equal("pass", checks[0].GetProperty("status").GetString());
        Assert.Equal("skipped", checks[2].GetProperty("status").GetString());
        Assert.Equal("not logged in", checks[2].GetProperty("reason").GetString());
        Assert.Equal(["it answers 401", "TLS accepted"], checks[0].GetProperty("verified").EnumerateArray().Select(v => v.GetString()));
        Assert.Equal(2, root.GetProperty("exitCode").GetInt32());
        Assert.Equal(1, root.GetProperty("summary").GetProperty("warnings").GetInt32());
    }
}
