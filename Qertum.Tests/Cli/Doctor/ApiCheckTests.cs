using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class ApiCheckTests
{
    private const string Probe = "https://ca.test/v1/me/access";

    private static Task<DoctorResult> Run(FakeHttp http, DoctorContext? context = null) =>
        new ApiCheck().RunAsync(context ?? DoctorTestSupport.Context(http), TestContext.Current.CancellationToken);

    [Fact]
    public async Task AnUnauthenticatedProbeAnswering401_Passes_AndMarksTheApiReachable()
    {
        var http = new FakeHttp().Route(Probe, HttpStatusCode.Unauthorized);
        var context = DoctorTestSupport.Context(http);

        var result = await Run(http, context);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.True(context.Shared.ApiReachable);
        Assert.Contains(result.Verified, v => v.Contains("authentication is enforced", StringComparison.Ordinal));
        Assert.Contains(result.Verified, v => v.Contains("TLS", StringComparison.Ordinal));
        Assert.NotEmpty(result.NotVerified);
    }

    [Fact]
    public async Task TheProbe_NeverCarriesTheToken()
    {
        var http = new FakeHttp().Route(Probe, HttpStatusCode.Unauthorized);

        await Run(http, DoctorTestSupport.Context(http, token: "super-secret"));

        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task PlainHttp_StillPasses_ButDoesNotClaimTls()
    {
        var http = new FakeHttp().Route("http://ca.test/v1/me/access", HttpStatusCode.Unauthorized);

        var result = await Run(http, DoctorTestSupport.Context(http, apiUrl: "http://ca.test"));

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.DoesNotContain(result.Verified, v => v.Contains("TLS", StringComparison.Ordinal));
        Assert.Contains(result.NotVerified, v => v.Contains("plain http", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A200WithoutAToken_Fails_BecauseAuthenticationIsNotEnforced()
    {
        var result = await Run(new FakeHttp().Route(Probe, HttpStatusCode.OK, "{}"));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("not enforced", result.Summary, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task AnyOtherStatus_Fails_AndSuggestsTheUrlMayNotBeTheApi(HttpStatusCode status)
    {
        var http = new FakeHttp().Route(Probe, status);
        var context = DoctorTestSupport.Context(http);

        var result = await Run(http, context);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(((int)status).ToString(), result.Summary, StringComparison.Ordinal);
        Assert.False(context.Shared.ApiReachable);
    }

    [Fact]
    public async Task ARedirect_IsReportedWithItsLocation_NotFollowed()
    {
        var result = await Run(new FakeHttp().Route(Probe, HttpStatusCode.MovedPermanently, "", location: "https://real.example/v1/me/access"));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("https://real.example/v1/me/access", result.Summary + result.Hint, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpRequestError.NameResolutionError, "cannot resolve")]
    [InlineData(HttpRequestError.ConnectionError, "cannot connect")]
    [InlineData(HttpRequestError.SecureConnectionError, "does not trust the server certificate")]
    public async Task TransportFailures_FailWithTheirOwnReason(HttpRequestError error, string expected)
    {
        var result = await Run(new FakeHttp().Throw(Probe, new HttpRequestException(error, "boom")));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(expected, result.Summary, StringComparison.Ordinal);
        Assert.NotNull(result.Hint);
    }

    [Fact]
    public async Task ATimeout_Fails_WithoutHanging()
    {
        var http = new FakeHttp().Hang(Probe);

        var result = await Run(http, DoctorTestSupport.Context(http, timeout: TimeSpan.FromMilliseconds(100)));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("no answer", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoApiUrl_Fails_AndSaysHowToSetOne()
    {
        var result = await Run(new FakeHttp(), DoctorTestSupport.Context(new FakeHttp(), apiUrl: null));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("--api-url", result.Hint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task APathPrefixInTheUrl_IsKept()
    {
        var http = new FakeHttp().Route("https://ca.test/qertum/v1/me/access", HttpStatusCode.Unauthorized);

        var result = await Run(http, DoctorTestSupport.Context(http, apiUrl: "https://ca.test/qertum"));

        Assert.Equal(DoctorStatus.Pass, result.Status);
    }
}
