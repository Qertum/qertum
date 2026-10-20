using System.Net;
using Qertum.Cli.Doctor;
using Qertum.Cli.Doctor.Checks;

namespace Qertum.Tests.Cli.Doctor;

public sealed class RevocationCheckTests
{
    private const string Crl = "https://ca.test/crl";
    private static readonly DateTime Now = DoctorTestSupport.Now.UtcDateTime;

    private static DoctorPki Root() => DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));

    private static Task<DoctorResult> Run(FakeHttp http, out DoctorContext context, DoctorPki? knownRoot = null,
        string? token = null, bool sessionAccepted = false, string? apiUrl = "https://ca.test")
    {
        context = DoctorTestSupport.Context(http, apiUrl: apiUrl, token: token);
        context.Shared.SessionAccepted = sessionAccepted;
        if (knownRoot is not null) context.Shared.Roots = [knownRoot.Certificate];
        return new RevocationCheck().RunAsync(context, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task AFreshCrlWithAVerifiedSignature_Passes_WithoutALogin()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)), "application/pkix-crl");

        var result = await Run(http, out _, root);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.Verified, v => v.Contains("signature", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Verified, v => v.Contains("nextUpdate", StringComparison.Ordinal));
        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task WithoutTheIssuerCertificate_TheSignatureIsNotVerified_AndSaidSo()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        var result = await Run(http, out _);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("signature not verified", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ALowRemainingWindow_Warns_AnExpiredCrlFails()
    {
        var root = Root();
        var low = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-6), Now.AddDays(1))); // 1 of 7 days left: 14%
        var expired = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-8), Now.AddDays(-1)));

        var warned = await Run(low, out _, root);
        var failed = await Run(expired, out _, root);

        Assert.Equal(DoctorStatus.Warn, warned.Status);
        Assert.Equal(DoctorStatus.Fail, failed.Status);
        Assert.Contains("expired", failed.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheBoundary_ExactlyAQuarterLeft_IsStillFine_JustUnderWarns()
    {
        var root = Root();
        var exactly = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-3), Now.AddDays(1)));       // 1 of 4: 25%
        var under = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-3), Now.AddHours(23)));      // just under 25%

        Assert.Equal(DoctorStatus.Pass, (await Run(exactly, out _, root)).Status);
        Assert.Equal(DoctorStatus.Warn, (await Run(under, out _, root)).Status);
    }

    [Fact]
    public async Task ACrlWithoutNextUpdate_Fails()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), null));

        Assert.Equal(DoctorStatus.Fail, (await Run(http, out _, root)).Status);
    }

    [Fact]
    public async Task ACrlSignedByAnotherKey_Fails()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6), signingKey: DoctorPki.NewKey()));

        var result = await Run(http, out _, root);

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("signature", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("<html>not a crl</html>")]
    [InlineData("")]
    public async Task GarbageWhereACrlShouldBe_Fails_NotACrash(string body)
    {
        var result = await Run(new FakeHttp().Route(Crl, HttpStatusCode.OK, body), out _, Root());

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("not a CRL", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACrlOverTheCap_IsRefused()
    {
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, new byte[(10 << 20) + 1]);

        var result = await Run(http, out _, Root());

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("larger than", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AConfiguredDistributionPoint_IsUsed_WhenTheCallerMayReadSettings()
    {
        var root = Root();
        var http = new FakeHttp()
            .Route("https://ca.test/v1/settings", HttpStatusCode.OK, """{"id":1,"organizationName":"Org","crlDistributionPoint":"https://crl.example.org/ca.crl"}""")
            .RouteBytes("https://crl.example.org/ca.crl", HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        var result = await Run(http, out _, root, token: "tok", sessionAccepted: true);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(http.Seen, s => s.Url == "https://crl.example.org/ca.crl" && s.Authorization is null);
        Assert.Contains(http.Seen, s => s.Url == "https://ca.test/v1/settings" && s.Authorization == "Bearer tok");
    }

    [Fact]
    public async Task NoDistributionPointConfigured_Warns_ButTheDefaultCrlIsStillChecked()
    {
        var root = Root();
        var http = new FakeHttp()
            .Route("https://ca.test/v1/settings", HttpStatusCode.OK, """{"id":1,"organizationName":"Org"}""")
            .RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        var result = await Run(http, out _, root, token: "tok", sessionAccepted: true);

        Assert.Equal(DoctorStatus.Warn, result.Status);
        Assert.Contains(result.Findings, f => f.Contains("distribution point", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithoutSettingsEdit_TheSettingIsNotVerified_NotAFailure()
    {
        var root = Root();
        var http = new FakeHttp()
            .Route("https://ca.test/v1/settings", HttpStatusCode.Forbidden)
            .RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        var result = await Run(http, out _, root, token: "tok", sessionAccepted: true);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("settings.edit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADistributionPointThatIsNotHttp_IsIgnored_NotFetched()
    {
        var root = Root();
        var http = new FakeHttp()
            .Route("https://ca.test/v1/settings", HttpStatusCode.OK, """{"id":1,"crlDistributionPoint":"file:///etc/passwd"}""")
            .RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        await Run(http, out _, root, token: "tok", sessionAccepted: true);

        Assert.DoesNotContain(http.Seen, s => s.Url.StartsWith("file:", StringComparison.Ordinal));
    }

    [Fact]
    public async Task NoApiUrlAndNoDistributionPoint_IsSkipped()
    {
        var result = await Run(new FakeHttp(), out _, apiUrl: null);

        Assert.Equal(DoctorStatus.Skipped, result.Status);
    }

    [Fact]
    public async Task AnUnreachableCrl_Fails_WithATransportReason()
    {
        var result = await Run(new FakeHttp().Throw(Crl, new HttpRequestException(HttpRequestError.ConnectionError, "refused")), out _, Root());

        Assert.Equal(DoctorStatus.Fail, result.Status);
        Assert.Contains("cannot connect", result.Summary, StringComparison.Ordinal);
    }

    private static Qertum.Services.IssuerResponse InUse(string name) => new(
        new Qertum.Services.IssuerId(Guid.NewGuid()), name, Qertum.Services.IssuerKind.Intermediate, null, Qertum.Services.IssuerKeyCustody.Online,
        Qertum.Services.IssuerStatus.Active, false, $"CN={name}", "01", "ECDSA-P256", null, null, null, [], [], [], [], null, null,
        DateTime.UtcNow, null, null, null, null);

    [Fact]
    public async Task LoggedOut_ItSaysTheOtherIssuersCrlsWereNotChecked()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));

        var result = await Run(http, out _, root);

        Assert.Equal(DoctorStatus.Pass, result.Status);
        Assert.Contains(result.NotVerified, v => v.Contains("other than the one served at this URL", StringComparison.Ordinal));
        Assert.Contains("ca.test", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithSeveralIssuersInUse_ItNamesHowManyOtherCrlsWereNotChecked()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));
        var context = DoctorTestSupport.Context(http);
        context.Shared.Roots = [root.Certificate];
        context.Shared.Issuers = [InUse("Root"), InUse("Issuing A"), InUse("Issuing B")];

        var result = await new RevocationCheck().RunAsync(context, TestContext.Current.CancellationToken);

        Assert.Contains(result.NotVerified, v => v.Contains("other 2 issuer(s)", StringComparison.Ordinal));
        Assert.DoesNotContain(result.NotVerified, v => v.Contains("needs a login", StringComparison.Ordinal));
    }

    [Fact]
    public async Task WithASingleIssuerInUse_NoOtherIssuerLineIsAdded()
    {
        var root = Root();
        var http = new FakeHttp().RouteBytes(Crl, HttpStatusCode.OK, root.Crl(Now.AddDays(-1), Now.AddDays(6)));
        var context = DoctorTestSupport.Context(http);
        context.Shared.Roots = [root.Certificate];
        context.Shared.Issuers = [InUse("Only")];

        var result = await new RevocationCheck().RunAsync(context, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(result.NotVerified, v => v.Contains("other", StringComparison.Ordinal) && v.Contains("issuer", StringComparison.Ordinal));
    }
}
