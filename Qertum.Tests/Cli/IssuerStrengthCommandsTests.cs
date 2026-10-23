using System.CommandLine;
using System.Net;
using System.Text;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class IssuerStrengthCommandsTests
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
    public void ExposesShowAndSetUnderCaStrength()
    {
        var ca = CaCommands.Build(new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output"));
        var strength = ca.Subcommands.Single(c => c.Name == "strength");
        Assert.Equal(["set", "show"], strength.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("off", IssuerStrengthMode.Off)]
    [InlineData("Warn", IssuerStrengthMode.Warn)]
    [InlineData("ENFORCE", IssuerStrengthMode.Enforce)]
    public void ParseStrength_IsCaseInsensitive(string text, IssuerStrengthMode expected) =>
        Assert.Equal(expected, CaCommands.ParseStrength(text));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("strict")]
    [InlineData("1")]
    [InlineData("99")]
    public void ParseStrength_RefusesAnythingElse(string? text) => Assert.Null(CaCommands.ParseStrength(text));

    [Fact]
    public async Task SetIssuerStrength_SendsPutWithTheModeName()
    {
        var handler = new Recording(HttpStatusCode.OK, "{}");
        var client = new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") });

        await client.SetIssuerStrengthAsync(IssuerStrengthMode.Enforce, TestContext.Current.CancellationToken);

        Assert.Equal(HttpMethod.Put, handler.Method);
        Assert.Equal("/v1/settings/issuer-strength", handler.PathAndQuery);
        Assert.Equal("{\"mode\":\"Enforce\"}", handler.Body);
    }
}
