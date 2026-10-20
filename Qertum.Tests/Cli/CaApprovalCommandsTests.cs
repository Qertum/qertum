using System.CommandLine;
using System.Net;
using System.Text;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class CaApprovalCommandsTests
{
    private static Command Ca() => CaCommands.Build(
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

    [Fact]
    public void ExposesShowAndSetUnderCaApproval()
    {
        var approval = Ca().Subcommands.Single(c => c.Name == "approval");
        Assert.Equal(["set", "show"], approval.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("independent", true, true)]
    [InlineData("WAIVED", true, false)]
    [InlineData("nonsense", false, false)]
    [InlineData("", false, false)]
    public void ParseMode_NamesBothModes_AndRefusesTheRest(string text, bool ok, bool require)
    {
        Assert.Equal(ok, CaCommands.ParseMode(text, out var parsed));
        if (ok) Assert.Equal(require, parsed);
    }

    [Theory]
    [InlineData(true, "independent")]
    [InlineData(false, "waived")]
    public void ShowText_NamesTheMode(bool require, string expected) =>
        Assert.Equal(expected, CaCommands.DescribeMode(require));

    [Fact]
    public void ConfirmationIsNeededOnlyWhenWaiving()
    {
        Assert.True(CaCommands.NeedsConfirmation(requireIndependent: false, yes: false));
        Assert.False(CaCommands.NeedsConfirmation(requireIndependent: false, yes: true));
        Assert.False(CaCommands.NeedsConfirmation(requireIndependent: true, yes: false));
    }

    [Fact]
    public async Task SetCaApprovalRule_SendsPutWithTheRuleBody()
    {
        var handler = new Recording(HttpStatusCode.OK, "{}");
        var client = new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") });
        await client.SetCaApprovalRuleAsync(false, TestContext.Current.CancellationToken);
        Assert.Equal(HttpMethod.Put, handler.Method);
        Assert.Equal("/v1/settings/ca-approval", handler.PathAndQuery);
        Assert.Equal("{\"requireIndependentApproval\":false}", handler.Body);
    }
}
