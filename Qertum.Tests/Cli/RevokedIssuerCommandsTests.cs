using System.CommandLine;
using System.Net;
using System.Text;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class RevokedIssuerCommandsTests
{
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
    public void ExposesShowAndSetUnderCaRevokedIssuer()
    {
        var ca = CaCommands.Build(new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output"));
        var strength = ca.Subcommands.Single(c => c.Name == "revoked-issuer");
        Assert.Equal(["set", "show"], strength.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("hardstop", RevokedIssuerMode.HardStop)]
    [InlineData("Retire", RevokedIssuerMode.Retire)]
    [InlineData("RETIRE", RevokedIssuerMode.Retire)]
    public void ParseRevokedIssuer_IsCaseInsensitive(string text, RevokedIssuerMode expected) =>
        Assert.Equal(expected, CaCommands.ParseRevokedIssuer(text));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("strict")]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("99")]
    public void ParseRevokedIssuer_RefusesAnythingElse(string? text) => Assert.Null(CaCommands.ParseRevokedIssuer(text));

    [Fact]
    public async Task SetRevokedIssuer_SendsPutWithTheModeName()
    {
        var handler = new Recording(HttpStatusCode.OK, "{}");
        var client = new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") });

        await client.SetRevokedIssuerModeAsync(RevokedIssuerMode.Retire, TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Put, handler.Method);
        Assert.Equal("/v1/settings/revoked-issuer", handler.PathAndQuery);
        Assert.Equal("{\"mode\":\"Retire\"}", handler.Body);
    }
}
