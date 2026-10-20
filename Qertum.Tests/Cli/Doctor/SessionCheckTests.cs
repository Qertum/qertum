using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class SessionCheckTests
{
    private const string Url = "https://ca.test/v1/me/access";

    private static (Task<DoctorResult> Result, DoctorContext Context) Run(FakeHttp http, bool apiReachable = true, string? token = "tok", string? problem = null)
    {
        var context = DoctorTestSupport.Context(http, token: token, tokenProblem: problem);
        context.Shared.ApiReachable = apiReachable;
        return (new SessionCheck().RunAsync(context, TestContext.Current.CancellationToken), context);
    }

    [Fact]
    public async Task AnAcceptedToken_Passes_WithRoles_AndMarksTheSession()
    {
        var http = new FakeHttp().Route(Url, HttpStatusCode.OK,
            """{"roles":["admin"],"isAdmin":true,"permissions":[{"name":"certificates.view","description":"","granted":true},{"name":"settings.edit","description":"","granted":false}]}""");

        var (task, context) = Run(http);
        var result = await task;

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains("admin", result.Summary, StringComparison.Ordinal);
        Assert.Contains(result.Verified, v => v.Contains("1 of 2 permissions", StringComparison.Ordinal));
        Assert.True(context.Shared.SessionAccepted);
        Assert.NotNull(context.Shared.Access);
        Assert.Equal("Bearer tok", Assert.Single(http.Seen).Authorization);
    }

    [Fact]
    public async Task ARejectedToken_Fails_WithTheLoginHint_AndLeavesTheSessionUnaccepted()
    {
        var (task, context) = Run(new FakeHttp().Route(Url, HttpStatusCode.Unauthorized));
        var result = await task;

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("rejected the token", result.Summary, StringComparison.Ordinal);
        Assert.Contains("qca auth login", result.Hint, StringComparison.Ordinal);
        Assert.False(context.Shared.SessionAccepted);
    }

    [Fact]
    public async Task NoToken_IsSkipped_WithTheReasonTheFactoryGave_AndNothingIsSent()
    {
        var http = new FakeHttp();

        var (task, _) = Run(http, token: null, problem: "the token expired at 2026-10-06 10:00 UTC: run 'qca auth login'");
        var result = await task;

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Contains("expired", result.Reason, StringComparison.Ordinal);
        Assert.Empty(http.Seen);
    }

    [Fact]
    public async Task AnUnreachableApi_SkipsWithoutSendingTheToken()
    {
        var http = new FakeHttp();

        var (task, _) = Run(http, apiReachable: false);
        var result = await task;

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Contains("api check", result.Reason, StringComparison.Ordinal);
        Assert.Empty(http.Seen);
    }

    [Fact]
    public async Task ATransportFailure_Fails_WithItsReason()
    {
        var (task, _) = Run(new FakeHttp().Throw(Url, new HttpRequestException(HttpRequestError.ConnectionError, "refused")));
        var result = await task;

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("cannot connect", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnAnswerThatIsNotMyAccess_Fails_NotACrash()
    {
        var (task, context) = Run(new FakeHttp().Route(Url, HttpStatusCode.OK, "[1,2,3]"));
        var result = await task;

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.False(context.Shared.SessionAccepted);
    }
}
