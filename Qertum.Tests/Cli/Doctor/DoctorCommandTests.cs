using System.CommandLine;
using System.Net;
using System.Text.Json;
using Qertum.Cli.Auth;
using Qertum.Cli.Commands;
using Qertum.Cli.Doctor;

namespace Qertum.Tests.Cli.Doctor;

public sealed class DoctorCommandTests
{
    private static readonly DateTime Now = DoctorTestSupport.Now.UtcDateTime;

    /// <summary>A complete, healthy deployment behind one fake HTTP handler.</summary>
    private static FakeHttp World(out DoctorPki root)
    {
        root = DoctorPki.Root("Example Root", Now.AddYears(-1), Now.AddYears(9));
        var issuing = root.Intermediate("Issuing CA", Now.AddYears(-1), Now.AddYears(4));
        var issuerId = Guid.NewGuid();
        return new FakeHttp()
            .Route("https://id.test/.well-known/openid-configuration", HttpStatusCode.OK, """{"issuer":"i","jwks_uri":"https://id.test/jwks"}""")
            .Route("https://id.test/jwks", HttpStatusCode.OK, """{"keys":[{"kty":"RSA"}]}""")
            .Route("https://ca.test/v1/me/access", HttpStatusCode.Unauthorized)
            .Route("https://ca.test/v1/issuers/trust-bundle?format=pem", HttpStatusCode.OK, DoctorPki.Pem(root.Certificate))
            .Route($"https://ca.test/v1/issuers/{issuerId}/chain?format=pem", HttpStatusCode.OK, DoctorPki.Pem(issuing.Certificate, root.Certificate))
            .RouteBytes("https://ca.test/crl", HttpStatusCode.OK, issuing.Crl(Now.AddDays(-1), Now.AddDays(6)));
    }

    private static DoctorContext Context(FakeHttp http, string? token) =>
        DoctorTestSupport.Context(http, token: token, roots: new FakeRootStore());

    [Fact]
    public void TheCommand_IsRegistered_WithATimeoutOption_AndTheStandardHelp()
    {
        var root = Qertum.Cli.CliRoot.Build();
        var doctor = root.Subcommands.Single(c => c.Name == "doctor");

        Assert.Contains(doctor.Options, o => o.Name == "--timeout");
        Assert.Contains("Needs:", doctor.Description, StringComparison.Ordinal);
        Assert.Contains("Exit codes:", doctor.Description, StringComparison.Ordinal);
        Assert.Contains("Example: qca doctor", doctor.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void TheChecksRunInTheDocumentedOrder() =>
        Assert.Equal(["api", "identity", "session", "issuers", "trust", "enrollment", "revocation", "server-reports"],
            DoctorCommands.AllChecks().Select(c => c.Id));

    [Fact]
    public async Task ALoggedOutRun_ExecutesTheChecksThatNeedNoLogin_AndSkipsTheRestWithReasons()
    {
        var http = World(out _);
        var context = Context(http, token: null);
        using var output = new StringWriter();

        var code = await DoctorCommands.RunAsync(context, json: true, output, TestContext.Current.CancellationToken);

        using var document = JsonDocument.Parse(output.ToString());
        var checks = document.RootElement.GetProperty("checks").EnumerateArray()
            .ToDictionary(c => c.GetProperty("id").GetString()!, c => c.GetProperty("status").GetString());
        Assert.Equal("pass", checks["api"]);
        Assert.Equal("pass", checks["identity"]);
        Assert.Equal("pass", checks["trust"]);
        Assert.Equal("pass", checks["revocation"]);
        Assert.Equal(["enrollment", "issuers", "server-reports", "session"],
            checks.Where(c => c.Value == "skipped").Select(c => c.Key).Order(StringComparer.Ordinal));
        Assert.Equal(0, code);
        Assert.All(http.Seen, s => Assert.Null(s.Authorization));
    }

    [Fact]
    public async Task NoRequestInAnyRun_CarriesTheTokenToAnythingButTheApisAuthenticatedCalls()
    {
        var http = World(out _);
        var context = Context(http, token: "super-secret");
        using var output = new StringWriter();

        await DoctorCommands.RunAsync(context, json: false, output, TestContext.Current.CancellationToken);

        var authenticated = new[] { "/v1/me/access", "/v1/ca/status", "/v1/issuers", "/v1/enrollment/options", "/v1/settings", "/v1/dashboard/attention" };
        foreach (var seen in http.Seen.Where(s => s.Authorization is not null))
        {
            var path = new Uri(seen.Url).AbsolutePath;
            Assert.Contains(path, authenticated);
            Assert.StartsWith("https://ca.test", seen.Url, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task TheTableOutput_EndsWithTheSummaryLine_AndShowsVerifiedAndNotVerified()
    {
        var context = Context(World(out _), token: null);
        using var output = new StringWriter();

        await DoctorCommands.RunAsync(context, json: false, output, TestContext.Current.CancellationToken);

        var text = output.ToString();
        Assert.Contains("PASS  api", text, StringComparison.Ordinal);
        Assert.Contains("SKIP  session", text, StringComparison.Ordinal);
        Assert.Contains("verified:", text, StringComparison.Ordinal);
        Assert.Contains("not verified:", text, StringComparison.Ordinal);
        Assert.Contains("Summary:", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AFailingApi_FailsTheRun_WithExitCode1_AndSkipsWhatDependsOnIt()
    {
        var http = new FakeHttp().Throw("https://ca.test/v1/me/access", new HttpRequestException(HttpRequestError.ConnectionError, "refused"))
            .Throw("https://ca.test/crl", new HttpRequestException(HttpRequestError.ConnectionError, "refused"));
        var context = Context(http, token: "tok");
        using var output = new StringWriter();

        var code = await DoctorCommands.RunAsync(context, json: false, output, TestContext.Current.CancellationToken);

        Assert.Equal(1, code);
        Assert.Contains("FAIL  api", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("SKIP  session", output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(http.Seen, s => s.Authorization is not null);
    }

    [Fact]
    public async Task AnExpiredSession_IsNotRefreshedOrCleared_AndDoctorStillRuns()
    {
        var loads = 0;
        var command = DoctorCommands.Build(
            new Option<string?>("--api-url"), new Option<string?>("--identity-url"), new Option<string?>("--token"), new Option<string>("--output"),
            () => World(out _), new FakeRootStore(), new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DoctorTestSupport.Now),
            () =>
            {
                loads++;
                return new CachedSession
                {
                    AccessToken = "old", RefreshToken = "refresh", ExpiresAt = DoctorTestSupport.Now.AddHours(-2),
                    ApiUrl = "https://ca.test", IdentityUrl = "https://id.test", Username = "alice"
                };
            });

        var parse = command.Parse("");
        var code = await parse.InvokeAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(1, loads);
        Assert.Equal(0, code);
    }

    [Theory]
    [InlineData("--timeout 0")]
    [InlineData("--timeout 121")]
    public async Task ATimeoutOutOfRange_IsRefused_WithExit1(string args)
    {
        var command = DoctorCommands.Build(
            new Option<string?>("--api-url"), new Option<string?>("--identity-url"), new Option<string?>("--token"), new Option<string>("--output"),
            () => new FakeHttp(), new FakeRootStore(), TimeProvider.System, () => null);

        var code = await command.Parse(args).InvokeAsync(cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(1, code);
    }
}
