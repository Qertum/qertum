using System.CommandLine;
using System.Net;
using System.Text;
using Qertum.Cli;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class IssuerKeyExportCommandTests : IDisposable
{
    private const string Id = "11111111-1111-1111-1111-111111111111";
    private static readonly IssuerId Issuer = new(Guid.Parse(Id));
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private readonly string _dir = Directory.CreateTempSubdirectory("qca-export-").FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    private sealed class Recording(HttpStatusCode status, byte[] body) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls.Add((request.Method, request.RequestUri!.AbsolutePath,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken)));
            return new HttpResponseMessage(status) { Content = new ByteArrayContent(body) };
        }
    }

    private static (CertificateRequestsApiClient Client, Recording Handler) ClientFor(HttpStatusCode status, string body)
    {
        var handler = new Recording(status, Encoding.ASCII.GetBytes(body));
        return (new(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") }), handler);
    }

    private static Command Issuers() => IssuerCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    [Theory]
    [InlineData($"export-key {Id} --file ca.key")]
    [InlineData($"export-pfx {Id} --file ca.pfx --pfx-password pw --no-chain --yes")]
    public void ValidInvocations_Parse(string line) => Assert.Empty(Issuers().Parse(line).Errors);

    [Theory]
    [InlineData($"export-key {Id}")]
    [InlineData($"export-pfx {Id} --file ca.pfx")]
    [InlineData($"export-pfx {Id} --pfx-password pw")]
    public void MissingRequiredOption_IsAParseError(string line) => Assert.NotEmpty(Issuers().Parse(line).Errors);

    [Theory]
    [InlineData("export-key")]
    [InlineData("export-pfx")]
    public void HelpCarriesTheWarning(string name) =>
        Assert.Contains("not a safe way to manage a CA private key", Issuers().Subcommands.Single(c => c.Name == name).Description);

    [Fact]
    public async Task ExportKey_WarnsConfirmsCallsTheEndpointAndWritesTheFile()
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        var path = Path.Combine(_dir, "ca.key");
        var asked = new List<string>();
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await IssuerCommands.ExportKeyAsync(client, Issuer, path, yes: false, q => { asked.Add(q); return true; }, output, error, Ct);

        Assert.Equal(0, exit);
        Assert.Equal((HttpMethod.Get, $"/v1/issuers/{Id}/private-key", null), Assert.Single(handler.Calls));
        Assert.Contains("PRIVATE KEY", File.ReadAllText(path));
        Assert.Contains("not a safe way to manage a CA private key", error.ToString());
        Assert.Single(asked);
        Assert.Contains($"written   {path}", output.ToString());
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }

    [Fact]
    public async Task ExportKey_Declined_CallsNothingAndWritesNothing()
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, "key");
        var path = Path.Combine(_dir, "ca.key");

        var exit = await IssuerCommands.ExportKeyAsync(client, Issuer, path, yes: false, _ => false, new StringWriter(), new StringWriter(), Ct);

        Assert.Equal(1, exit);
        Assert.Empty(handler.Calls);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task ExportKey_Yes_SkipsThePrompt_ButStillWarns()
    {
        var (client, _) = ClientFor(HttpStatusCode.OK, "key");
        var error = new StringWriter();

        var exit = await IssuerCommands.ExportKeyAsync(client, Issuer, Path.Combine(_dir, "ca.key"), yes: true,
            _ => throw new InvalidOperationException("must not prompt"), new StringWriter(), error, Ct);

        Assert.Equal(0, exit);
        Assert.Contains("not a safe way", error.ToString());
    }

    [Fact]
    public async Task ExportKey_NeverOverwritesAnExistingFile()
    {
        var (client, _) = ClientFor(HttpStatusCode.OK, "new key");
        var path = Path.Combine(_dir, "ca.key");
        await File.WriteAllTextAsync(path, "precious", Ct);
        var error = new StringWriter();

        var exit = await IssuerCommands.ExportKeyAsync(client, Issuer, path, yes: true, _ => true, new StringWriter(), error, Ct);

        Assert.Equal(1, exit);
        Assert.Equal("precious", File.ReadAllText(path));
        Assert.Contains("cannot write", error.ToString());
    }

    [Fact]
    public async Task ExportKey_ServerRefusal_Throws_AndWritesNothing()
    {
        var (client, _) = ClientFor(HttpStatusCode.NotFound, "{\"title\":\"Not Found\",\"detail\":\"This server holds no private key for that issuer.\"}");
        var path = Path.Combine(_dir, "ca.key");

        await Assert.ThrowsAsync<ApiProblemException>(() =>
            IssuerCommands.ExportKeyAsync(client, Issuer, path, yes: true, _ => true, new StringWriter(), new StringWriter(), Ct));

        Assert.False(File.Exists(path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ExportPfx_PostsPasswordAndChainChoice_AndWritesTheFile(bool includeChain)
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, "pfx-bytes");
        var path = Path.Combine(_dir, "ca.pfx");

        var exit = await IssuerCommands.ExportPfxAsync(client, Issuer, path, "s3cret", includeChain, yes: true, _ => true,
            new StringWriter(), new StringWriter(), Ct);

        Assert.Equal(0, exit);
        var call = Assert.Single(handler.Calls);
        Assert.Equal((HttpMethod.Post, $"/v1/issuers/{Id}/pfx"), (call.Method, call.Path));
        Assert.Contains("\"password\":\"s3cret\"", call.Body);
        Assert.Contains($"\"includeChain\":{includeChain.ToString().ToLowerInvariant()}", call.Body);
        Assert.Equal("pfx-bytes", File.ReadAllText(path));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ExportPfx_EmptyPassword_FailsBeforeAnyCall(string? password)
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, "x");
        var error = new StringWriter();

        var exit = await IssuerCommands.ExportPfxAsync(client, Issuer, Path.Combine(_dir, "ca.pfx"), password, true, yes: true, _ => true,
            new StringWriter(), error, Ct);

        Assert.Equal(1, exit);
        Assert.Empty(handler.Calls);
        Assert.Contains("must not be empty", error.ToString());
    }

    [Fact]
    public void ExposesBothCommands() =>
        Assert.Contains(CliRoot.Build().Subcommands.Single(c => c.Name == "issuers").Subcommands.Select(c => c.Name), n => n == "export-key");
}
