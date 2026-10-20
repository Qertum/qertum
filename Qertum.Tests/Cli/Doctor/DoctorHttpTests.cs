using System.Net;
using System.Security.Authentication;
using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class DoctorHttpTests
{
    private static readonly Uri Url = new("https://ca.test/v1/me/access");

    private static Task<DoctorResponse> Get(FakeHttp http, string? token = null, int max = 1 << 20, TimeSpan? timeout = null) =>
        DoctorHttp.GetAsync(DoctorTestSupport.Context(http, timeout: timeout), Url, token, max, TestContext.Current.CancellationToken);

    [Fact]
    public async Task AnAnswer_CarriesStatusAndBody()
    {
        var response = await Get(new FakeHttp().Route(Url.ToString(), HttpStatusCode.Unauthorized, "nope"));

        Assert.True(response.Ok);
        Assert.Equal(HttpStatusCode.Unauthorized, response.Status);
        Assert.Equal("nope", response.Text);
    }

    [Fact]
    public async Task ABearerTokenIsSentOnlyWhenAsked()
    {
        var http = new FakeHttp().Route(Url.ToString(), HttpStatusCode.OK);

        await Get(http);
        await Get(http, token: "secret");

        Assert.Null(http.Seen[0].Authorization);
        Assert.Equal("Bearer secret", http.Seen[1].Authorization);
    }

    [Theory]
    [InlineData(HttpRequestError.NameResolutionError, "NameResolution")]
    [InlineData(HttpRequestError.ConnectionError, "ConnectionRefused")]
    [InlineData(HttpRequestError.SecureConnectionError, "Tls")]
    [InlineData(HttpRequestError.Unknown, "Other")]
    public async Task TransportFailures_AreClassified(HttpRequestError error, string expected)
    {
        var response = await Get(new FakeHttp().Throw(Url.ToString(), new HttpRequestException(error, "boom")));

        Assert.False(response.Ok);
        Assert.Equal(expected, response.Failure.ToString());
        Assert.Null(response.Status);
    }

    [Fact]
    public async Task ACertificateExceptionInsideTheFailure_IsTls()
    {
        var inner = new AuthenticationException("The remote certificate is invalid");
        var response = await Get(new FakeHttp().Throw(Url.ToString(), new HttpRequestException(HttpRequestError.Unknown, "x", inner)));

        Assert.Equal(DoctorFailureKind.Tls, response.Failure);
    }

    [Fact]
    public async Task ASilentServer_TimesOut_NotHangs()
    {
        var response = await Get(new FakeHttp().Hang(Url.ToString()), timeout: TimeSpan.FromMilliseconds(100));

        Assert.Equal(DoctorFailureKind.Timeout, response.Failure);
    }

    [Fact]
    public async Task ABodyOverTheCap_IsRefused_NotRead()
    {
        var response = await Get(new FakeHttp().RouteBytes(Url.ToString(), HttpStatusCode.OK, new byte[2048]), max: 1024);

        Assert.Equal(DoctorFailureKind.TooLarge, response.Failure);
    }

    [Fact]
    public async Task ARedirect_IsNotFollowed_AndKeepsItsLocation()
    {
        var response = await Get(new FakeHttp().Route(Url.ToString(), HttpStatusCode.MovedPermanently, "", location: "https://elsewhere.test/v1/me/access"));

        Assert.Equal(HttpStatusCode.MovedPermanently, response.Status);
        Assert.Equal("https://elsewhere.test/v1/me/access", response.Location);
    }

    [Theory]
    [InlineData("NameResolution", "cannot resolve")]
    [InlineData("ConnectionRefused", "cannot connect")]
    [InlineData("Tls", "does not trust the server certificate")]
    [InlineData("Timeout", "no answer")]
    [InlineData("TooLarge", "larger than")]
    public void Explain_NamesTheHostAndTheReason(string kind, string expected)
    {
        var (summary, hint) = DoctorHttp.Explain(new DoctorResponse(null, [], null, Enum.Parse<DoctorFailureKind>(kind), "detail"), Url, TimeSpan.FromSeconds(10));

        Assert.Contains("ca.test", summary, StringComparison.Ordinal);
        Assert.Contains(expected, summary, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(hint));
    }

    [Theory]
    [InlineData("https://h/qertum/", "/v1/x", "https://h/qertum/v1/x")]
    [InlineData("https://h/qertum", "/v1/x", "https://h/qertum/v1/x")]
    [InlineData("https://h:8443", "/crl", "https://h:8443/crl")]
    public void Combine_KeepsAPathPrefix_AndOneSlash(string baseUrl, string path, string expected) =>
        Assert.Equal(expected, DoctorUrls.Combine(baseUrl, path).ToString());

    [Theory]
    [InlineData("https://ok.test/x", true)]
    [InlineData("http://ok.test/x", true)]
    [InlineData("file:///etc/passwd", false)]
    [InlineData("ftp://host/x", false)]
    [InlineData("not a url", false)]
    [InlineData(null, false)]
    public void TryHttp_AcceptsOnlyHttpAndHttps(string? value, bool expected) =>
        Assert.Equal(expected, DoctorUrls.TryHttp(value, out _));
}
