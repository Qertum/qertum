using System.CommandLine;
using Bunit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Web.Auth;
using System.Text.RegularExpressions;
using Qertum.Cli;
using Qertum.Web;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

/// <summary>
/// The "Automation snippets" examples are text an operator pastes into a pipeline. They must stay true to the real
/// <c>qca</c> command tree, carry only the deployment's own URLs and the page's own ids, and never carry a credential.
/// </summary>
public sealed class AutomationSnippetTests
{
    private const string Api = "https://api.contoso.local";
    private const string Identity = "https://id.contoso.local";
    private static readonly Guid Id = Guid.Parse("3f2c9a1e-0000-0000-0000-000000000000");

    private static IEnumerable<AutomationSnippet> All(string api = Api) =>
        Enum.GetValues<AutomationOperation>().SelectMany(op => AutomationSnippetCatalog.For(op, api, Identity, Id));

    [Fact]
    public void EveryQcaLine_ParsesAgainstTheRealCommandTree()
    {
        var root = CliRoot.Build();
        // A qca invocation ends at a pipe, a closing $( ) or a stderr redirect; the shell around it is not qca's to parse.
        var lines = All().SelectMany(s => Regex.Matches(s.Command, @"qca [^|)\n]+").Select(m => m.Value))
            .Select(l => Regex.Replace(l, @"\s+2>\s*\S+$", "").Trim()).ToList();
        Assert.NotEmpty(lines);

        foreach (var line in lines)
        {
            // Typed placeholders (ids, counts) stand in with a value of the right type; the rest stay blanks.
            var typed = Regex.Replace(Regex.Replace(line["qca ".Length..].Replace("\"$REQUEST_ID\"", Id.ToString()), "<[a-z-]*id>", Id.ToString()), "<count>", "1");
            var result = root.Parse(typed);
            Assert.True(result.Errors.Count == 0, $"'{line}': {string.Join("; ", result.Errors.Select(e => e.Message))}");
        }
    }

    [Fact]
    public void EveryOperation_HasAtLeastOneSnippet_AndTheFailureExampleNamesTheCorrelationId()
    {
        Assert.All(Enum.GetValues<AutomationOperation>(), op =>
            Assert.NotEmpty(AutomationSnippetCatalog.For(op, Api, Identity, Id)));

        var failure = AutomationSnippetCatalog.For(AutomationOperation.Setup, Api, Identity).Single(s => s.Id == "failure");
        Assert.Contains("correlation id:", failure.Command);
        Assert.Contains("Exit codes", failure.Description);
    }

    [Fact]
    public void Snippets_CarryTheConfiguredUrlsAndThePageId()
    {
        var setup = AutomationSnippetCatalog.For(AutomationOperation.Setup, Api + "/", Identity + "/").First(s => s.Id == "setup").Command;
        Assert.Contains($"QERTUM_API_URL={Api}\n", setup);
        // The token endpoint comes from the identity provider's discovery document, never from an assumed path.
        Assert.Contains($"{Identity}/.well-known/openid-configuration", setup);
        Assert.Contains("token_endpoint", setup);
        Assert.DoesNotContain("/connect/token", setup);

        Assert.Contains($"{Api}/v1/certificate-requests/{Id}/revoke",
            AutomationSnippetCatalog.For(AutomationOperation.Revoke, Api, Identity, Id).Single().Command);
        Assert.All(AutomationSnippetCatalog.For(AutomationOperation.Renew, Api, Identity, Id), s => Assert.Contains(Id.ToString(), s.Command));
    }

    [Fact]
    public void WithoutAConfiguredApiUrl_PrintsTheBlank_NotAGuess()
    {
        var commands = All(api: "").Select(s => s.Command).ToList();

        Assert.Contains(commands, c => c.Contains($"QERTUM_API_URL={AutomationSnippetCatalog.ApiUrlBlank}"));
        Assert.DoesNotContain(commands, c => c.Contains("localhost") || c.Contains("apiservice"));
    }

    [Fact]
    public void Snippets_NeverSwitchOffTlsOrCarryACredential()
    {
        foreach (var s in All())
        {
            Assert.DoesNotMatch(@"(^|\s)(-k|--insecure)(\s|$)", s.Command);
            Assert.DoesNotContain("--token", s.Command);
            // Every secret-bearing field is an angle-bracket blank or the token variable, never a literal.
            foreach (Match m in Regex.Matches(s.Command, @"(client_secret|client_id|password)=(\S+)"))
                Assert.StartsWith("<", m.Groups[2].Value);
            foreach (Match m in Regex.Matches(s.Command, @"Bearer (\S+)"))
                Assert.Equal("$QERTUM_TOKEN\"", m.Groups[1].Value);
        }
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("https://api.contoso.local", true)]
    [InlineData("http://localhost:8082", true)]
    [InlineData("api.contoso.local", false)]
    [InlineData("ftp://api.contoso.local", false)]
    public void ApiUrlOption_AcceptsEmptyOrAbsoluteHttpOnly(string url, bool valid) =>
        Assert.Equal(valid, AutomationOptions.IsValid(new AutomationOptions { ApiUrl = url }));

    [Fact]
    public void TheFold_IsClosedByDefault_StartsWithTheSetup_AndUsesTheConfiguredApiUrl()
    {
        using var context = new BunitContext();
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(Options.Create(new AutomationOptions { ApiUrl = Api }));
        context.Services.AddSingleton(new IdentityAuthority(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["IdentityService:Authority"] = Identity }).Build()));

        var cut = context.Render<AutomationSnippets>(p => p
            .Add(c => c.Operations, [AutomationOperation.Renew, AutomationOperation.Revoke])
            .Add(c => c.TargetId, Id));

        var fold = cut.Find("details[data-test='automation-snippets']");
        Assert.False(fold.HasAttribute("open"));
        Assert.Equal(["setup", "failure", "renew", "renew-deploy", "revoke"], cut.FindAll("[data-snippet]").Select(e => e.GetAttribute("data-snippet")));
        Assert.Contains($"QERTUM_API_URL={Api}", cut.Markup);
        Assert.Contains($"qca cert renew {Id}", cut.Markup);
    }

    [Fact]
    public void TheMetadataExample_ShowsThenSetsForThePageCertificate()
    {
        var snippet = AutomationSnippetCatalog.For(AutomationOperation.Metadata, Api, Identity, Id).Single();

        Assert.Equal("metadata-set", snippet.Id);
        Assert.Contains($"qca cert metadata show {Id}", snippet.Command);
        Assert.Contains($"qca cert metadata set {Id} --owner-team", snippet.Command);
    }
}
