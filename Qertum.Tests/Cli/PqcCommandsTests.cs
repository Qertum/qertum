using System.CommandLine;
using System.Net;
using System.Text;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class PqcCommandsTests
{
    private static Command Pqc() => PqcCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    private sealed class Recording(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpMethod? Method { get; private set; }
        public string? PathAndQuery { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Method = request.Method;
            PathAndQuery = request.RequestUri!.PathAndQuery;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private static (CertificateRequestsApiClient Client, Recording Handler) Client(HttpStatusCode status = HttpStatusCode.OK, string body = "{}")
    {
        var handler = new Recording(status, body);
        return (new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") }), handler);
    }

    [Fact]
    public void ExposesTheStageAndExceptionCommands()
    {
        var pqc = Pqc();
        Assert.Equal(["exceptions", "report", "stage"], pqc.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
        Assert.Equal(["set", "show", "template"],
            pqc.Subcommands.Single(c => c.Name == "stage").Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
        Assert.Equal(["create", "list", "revoke"],
            pqc.Subcommands.Single(c => c.Name == "exceptions").Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("warn", PqcStage.Warn)]
    [InlineData("ENFORCE", PqcStage.Enforce)]
    [InlineData("Off", PqcStage.Off)]
    public void ParseStage_IsCaseInsensitive(string text, PqcStage expected) =>
        Assert.Equal(expected, PqcCommands.ParseStage(text));

    [Theory]
    [InlineData("nonsense")]
    [InlineData("")]
    [InlineData("7")]
    public void ParseStage_RefusesAnythingElse(string text) => Assert.Null(PqcCommands.ParseStage(text));

    [Theory]
    [InlineData(null, false, "Pass --stage, or --clear.")]
    [InlineData("warn", true, "Pass either --stage or --clear, not both.")]
    public void TemplateStage_NeedsExactlyOneOfStageOrClear(string? stage, bool clear, string expected) =>
        Assert.Equal(expected, PqcCommands.ValidateTemplateStageArguments(stage, clear));

    [Fact]
    public void TemplateStage_AcceptsStageOrClear()
    {
        Assert.Null(PqcCommands.ValidateTemplateStageArguments("warn", clear: false));
        Assert.Null(PqcCommands.ValidateTemplateStageArguments(null, clear: true));
        Assert.NotNull(PqcCommands.ValidateTemplateStageArguments("sideways", clear: false));
    }

    [Theory]
    [InlineData("rsa", PqcExceptionFamily.Rsa)]
    [InlineData("ECDSA", PqcExceptionFamily.Ecdsa)]
    public void ParseFamily_IsCaseInsensitive(string text, PqcExceptionFamily expected) =>
        Assert.Equal(expected, PqcCommands.ParseFamily(text));

    [Fact]
    public void ParseFamily_RefusesCompliantFamilies() => Assert.Null(PqcCommands.ParseFamily("ml-dsa"));

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(3650, true)]
    [InlineData(3651, false)]
    public void Days_MustBeOneToThreeThousandSixHundredFifty(int days, bool ok) =>
        Assert.Equal(ok, PqcCommands.ValidateDays(days) is null);

    [Fact]
    public void Create_MapsEveryOption_AndComputesTheExpiry()
    {
        var parsed = Pqc().Parse("exceptions create --template WebServer --name legacy.corp.example --family rsa --days 30 --reason \"old load balancer\"");
        Assert.Empty(parsed.Errors);
        var now = new DateTime(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);

        var request = PqcCommands.BuildCreateRequest(parsed, now);

        Assert.Equal("WebServer", request!.TemplateTypeKey);
        Assert.Equal("legacy.corp.example", request.NamePattern);
        Assert.Equal(PqcExceptionFamily.Rsa, request.Family);
        Assert.Equal(now.AddDays(30), request.ExpiresAtUtc);
        Assert.Equal("old load balancer", request.Reason);
    }

    [Fact]
    public void Create_RequiresItsOptions() =>
        Assert.NotEmpty(Pqc().Parse("exceptions create --template WebServer").Errors);

    [Fact]
    public void Warnings_AreFormattedOnePerLine()
    {
        Assert.Equal(["warning: a", "warning: b"], CliApi.FormatWarnings(["a", "b"]));
        Assert.Empty(CliApi.FormatWarnings(null));
    }

    [Fact]
    public async Task SetPqcStage_PutsTheStageName()
    {
        var (client, handler) = Client(body: """{"id":1,"pqcStage":"Warn"}""");

        var settings = await client.SetPqcStageAsync(PqcStage.Warn, TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Put, handler.Method);
        Assert.Equal("/v1/settings/pqc-stage", handler.PathAndQuery);
        Assert.Equal("""{"stage":"Warn"}""", handler.Body);
        Assert.Equal(PqcStage.Warn, settings.PqcStage);
    }

    [Fact]
    public async Task SetTemplatePqcStage_Clear_SendsNull()
    {
        var (client, handler) = Client(body: "{}");
        var id = new CertificateTemplateId(Guid.NewGuid());

        await client.SetTemplatePqcStageAsync(id, null, TestContext.Current.CancellationToken);

        Assert.Equal($"/v1/certificate-templates/{id}/pqc-stage", handler.PathAndQuery);
        Assert.Equal("""{"stage":null}""", handler.Body);
    }

    [Fact]
    public async Task ListExceptions_SendsIncludeInactive()
    {
        var (client, handler) = Client(body: "[]");

        await client.GetPqcExceptionsAsync(includeInactive: true, TestContext.Current.CancellationToken);

        Assert.Equal("/v1/pqc-exceptions?includeInactive=true", handler.PathAndQuery);
    }

    [Fact]
    public async Task RevokeException_PostsToTheRevokeRoute()
    {
        var (client, handler) = Client(body: "{}");
        var id = new PqcExceptionId(Guid.NewGuid());

        await client.RevokePqcExceptionAsync(id, TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal($"/v1/pqc-exceptions/{id}/revoke", handler.PathAndQuery);
    }

    [Fact]
    public async Task ForbiddenCall_ThrowsAProblemThatCarriesTheStatus()
    {
        var (client, _) = Client(HttpStatusCode.Forbidden, """{"title":"Forbidden","status":403}""");

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() =>
            client.SetPqcStageAsync(PqcStage.Off, TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.Forbidden, ex.StatusCode);
        Assert.Equal("managing PQC enforcement needs the admin role", PqcCommands.AdminHint);
    }
}
