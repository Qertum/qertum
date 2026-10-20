using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class ServerReportsCheckTests
{
    private const string Url = "https://ca.test/v1/dashboard/attention";

    private static string Item(string kind, string severity, string title) =>
        $$"""{"kind":"{{kind}}","severity":"{{severity}}","count":1,"title":"{{title}}","explanation":"","evidence":[],"actionLabel":"","actionHref":""}""";

    private static string Report(string items = "", string withheld = "", string unavailable = "") =>
        $$"""{"generatedAtUtc":"2026-10-07T12:00:00Z","items":[{{items}}],"withheldKinds":[{{withheld}}],"unavailableKinds":[{{unavailable}}]}""";

    private static Task<DoctorResult> Run(FakeHttp http, bool sessionAccepted = true)
    {
        var context = DoctorTestSupport.Context(http);
        context.Shared.SessionAccepted = sessionAccepted;
        return new ServerReportsCheck().RunAsync(context, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AnEmptyReport_Passes_AndSaysWhoseChecksThey_Are()
    {
        var result = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, Report()));

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("what your role may see", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AWarningAndACritical_AreWarnAndFail_AndListedAsFindings()
    {
        var items = Item("AgingApprovals", "Warning", "2 requests wait too long") + "," + Item("CaExpiry", "Critical", "The CA certificate expired");

        var result = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, Report(items)));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("2 requests wait too long", StringComparison.Ordinal));
        Assert.Contains(result.Findings, f => f.Contains("The CA certificate expired", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OnlyWarnings_Warn()
    {
        var result = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, Report(Item("RecoveryStatus", "Warning", "Last backup is 5 days old"))));

        Assert.Equal(DoctorStatus.Warn, result.Status);
    }

    [Fact]
    public async Task UnavailableKinds_AreUnknown_NeverOk()
    {
        var result = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, Report(unavailable: "\"CaExpiry\"")));

        Assert.Equal(DoctorStatus.Warn, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("CaExpiry", StringComparison.Ordinal) && f.Contains("unknown", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithheldKinds_AreListedAsNotChecked_AndDoNotChangeTheStatus()
    {
        var result = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, Report(withheld: "\"FailedWebhookDeliveries\",\"CaExpiry\"")));

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("FailedWebhookDeliveries", StringComparison.Ordinal) && v.Contains("CaExpiry", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NoSession_IsSkipped_WithoutAnyRequest()
    {
        var http = new FakeHttp();

        var result = await Run(http, sessionAccepted: false);

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Empty(http.Seen);
    }

    [Fact]
    public async Task ARejectedCall_AndAWrongShape_BothFail()
    {
        var rejected = await Run(new FakeHttp().Route(Url, HttpStatusCode.InternalServerError));
        var wrongShape = await Run(new FakeHttp().Route(Url, HttpStatusCode.OK, "[1]"));

        Assert.Equal(DoctorStatus.Fail, rejected.Status);
        Assert.Equal(DoctorStatus.Fail, wrongShape.Status);
    }
}
