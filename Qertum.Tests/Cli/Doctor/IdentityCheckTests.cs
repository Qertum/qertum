using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class IdentityCheckTests
{
    private const string Discovery = "https://id.test/.well-known/openid-configuration";
    private const string Jwks = "https://id.test/.well-known/jwks";

    private static Task<DoctorResult> Run(FakeHttp http, string? identityUrl = "https://id.test", string? token = "tok") =>
        new IdentityCheck().RunAsync(DoctorTestSupport.Context(http, identityUrl: identityUrl, token: token), TestContext.Current.CancellationToken);

    private static FakeHttp Healthy() => new FakeHttp()
        .Route(Discovery, HttpStatusCode.OK, """{"issuer":"https://id.test/","jwks_uri":"https://id.test/.well-known/jwks"}""")
        .Route(Jwks, HttpStatusCode.OK, """{"keys":[{"kty":"RSA","kid":"1"}]}""");

    [Fact]
    public async Task ADiscoveryDocumentAndANonEmptyKeySet_Passes()
    {
        var result = await Run(Healthy());

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.Verified, v => v.Contains("1 signing key", StringComparison.Ordinal));
        Assert.Contains(result.NotVerified, v => v.Contains("login would succeed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NeitherRequestCarriesTheToken()
    {
        var http = Healthy();

        await Run(http, token: "super-secret");

        Assert.Equal(2, http.Seen.Count);
        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task NoIdentityUrl_IsSkipped_WithAReason()
    {
        var result = await Run(new FakeHttp(), identityUrl: null);

        Assert.Equal(DoctorStatus.Skipped, result.Status);
        Assert.Contains("--identity-url", result.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"issuer":"https://id.test/"}""")]
    [InlineData("""{"jwks_uri":"https://id.test/.well-known/jwks"}""")]
    [InlineData("""[]""")]
    [InlineData("not json")]
    public async Task ADiscoveryDocumentWithoutIssuerAndJwksUri_Fails(string body)
    {
        var result = await Run(new FakeHttp().Route(Discovery, HttpStatusCode.OK, body));

        Assert.Equal(DoctorStatus.Fail, result.Status);
    }

    [Fact]
    public async Task AnEmptyKeySet_Fails()
    {
        var http = new FakeHttp()
            .Route(Discovery, HttpStatusCode.OK, """{"issuer":"i","jwks_uri":"https://id.test/.well-known/jwks"}""")
            .Route(Jwks, HttpStatusCode.OK, """{"keys":[]}""");

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("no signing keys", result.Summary, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("file:///etc/passwd")]
    [InlineData("ftp://id.test/jwks")]
    public async Task AJwksUriThatIsNotHttp_IsRefused_AndNeverFetched(string jwksUri)
    {
        var http = new FakeHttp().Route(Discovery, HttpStatusCode.OK, $$"""{"issuer":"i","jwks_uri":"{{jwksUri}}"}""");

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Single(http.Seen);
    }

    [Fact]
    public async Task A404OnDiscovery_Fails_AndNamesTheUrl()
    {
        var result = await Run(new FakeHttp());

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("404", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnUnreachableIdentityProvider_Fails_WithATransportReason()
    {
        var result = await Run(new FakeHttp().Throw(Discovery, new HttpRequestException(HttpRequestError.ConnectionError, "refused")));

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("cannot connect", result.Summary, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "answered 404")]
    [InlineData(HttpStatusCode.InternalServerError, "answered 500")]
    public async Task AJwksThatCannotBeFetched_IsReportedByItsStatus_NotAsNoKeys(HttpStatusCode status, string expected)
    {
        var http = new FakeHttp()
            .Route(Discovery, HttpStatusCode.OK, """{"issuer":"i","jwks_uri":"https://id.test/.well-known/jwks"}""")
            .Route(Jwks, status);

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains(expected, result.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("no signing keys", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARedirectingJwks_NamesWhereItRedirects()
    {
        var http = new FakeHttp()
            .Route(Discovery, HttpStatusCode.OK, """{"issuer":"i","jwks_uri":"https://id.test/.well-known/jwks"}""")
            .Route(Jwks, HttpStatusCode.Found, "", location: "https://other.test/jwks");

        var result = await Run(http);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("https://other.test/jwks", result.Summary + result.Hint, StringComparison.Ordinal);
    }
}
