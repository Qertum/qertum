using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class EnrollmentCheckTests
{
    private const string Options = "https://ca.test/v1/enrollment/options";
    private const string Directory = "https://acme.test/acme/directory";
    private const string Cacerts = "https://est.test/.well-known/est/cacerts";

    private static string OptionsJson(bool acme = true, bool est = true) =>
        "{\"purposes\":[],\"templates\":[],\"pqcStage\":\"Off\"" +
        (acme ? ",\"acme\":{\"templateTypeKey\":\"WebServer\",\"directoryUrl\":\"" + Directory + "\",\"externalAccountBindingRequired\":false,\"autoApprove\":false}" : "") +
        (est ? ",\"est\":{\"templateTypeKey\":\"WebServer\",\"baseUrl\":\"https://est.test/.well-known/est\",\"autoApprove\":false}" : "") + "}";

    private const string GoodDirectory = """{"newNonce":"https://acme.test/n","newAccount":"https://acme.test/a","newOrder":"https://acme.test/o"}""";

    private static Task<DoctorResult> Run(FakeHttp http, bool sessionAccepted = true)
    {
        var context = DoctorTestSupport.Context(http);
        context.Shared.SessionAccepted = sessionAccepted;
        return new EnrollmentCheck().RunAsync(context, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AReachableDirectoryAndEst_Pass()
    {
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson())
            .Route(Directory, HttpStatusCode.OK, GoodDirectory).Route(Cacerts, HttpStatusCode.Unauthorized);

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.Verified, v => v.Contains("newOrder", StringComparison.Ordinal));
        Assert.Contains(result.Verified, v => v.Contains("authentication", StringComparison.Ordinal));
        Assert.Contains(result.NotVerified, v => v.Contains("enrollment would succeed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task OnlyTheOptionsRequestCarriesTheToken()
    {
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson())
            .Route(Directory, HttpStatusCode.OK, GoodDirectory).Route(Cacerts, HttpStatusCode.OK, "");

        await Run(http);

        Assert.Equal("Bearer tok", http.Seen.Single(s => s.Url == Options).Authorization);
        Assert.All(http.Seen.Where(s => s.Url != Options), s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task ADirectoryMissingNewOrder_Fails()
    {
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson(est: false))
            .Route(Directory, HttpStatusCode.OK, """{"newNonce":"x","newAccount":"y"}""");

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("newOrder", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task AnEstEndpointThatIsNeither200Nor401_Fails(HttpStatusCode status)
    {
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson(acme: false)).Route(Cacerts, status);

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
    }

    [Fact]
    public async Task AnUnreachableRoute_Fails_WithATransportReason()
    {
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson(est: false))
            .Throw(Directory, new HttpRequestException(HttpRequestError.SecureConnectionError, "tls"));

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("does not trust the server certificate", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnAcmeUrlThatIsNotHttp_IsRefused_AndNeverFetched()
    {
        var json = OptionsJson(est: false).Replace(Directory, "file:///etc/passwd", StringComparison.Ordinal);
        var http = new FakeHttp().Route(Options, HttpStatusCode.OK, json);

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Single(http.Seen);
    }

    [Fact]
    public async Task NeitherRouteConfigured_IsSkipped()
    {
        var result = await Run(new FakeHttp().Route(Options, HttpStatusCode.OK, OptionsJson(acme: false, est: false)));

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Contains("no ACME or EST route", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutCertificatesCreate_TheCheckIsSkipped_NotFailed()
    {
        var result = await Run(new FakeHttp().Route(Options, HttpStatusCode.Forbidden));

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Contains("certificates.create", result.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NoSession_IsSkipped_WithoutAnyRequest()
    {
        var http = new FakeHttp();

        var result = await Run(http, sessionAccepted: false);

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Empty(http.Seen);
    }
}
