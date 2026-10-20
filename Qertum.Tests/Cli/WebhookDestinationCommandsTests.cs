using System.CommandLine;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class WebhookDestinationCommandsTests
{
    private static Command Webhooks() => WebhookCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    [Fact]
    public void DestinationsExposeAllManagementCommands()
    {
        var destinations = Assert.Single(Webhooks().Subcommands, command => command.Name == "destinations");
        Assert.Equal(["add", "delete", "disable", "enable", "list", "mode"],
            destinations.Subcommands.Select(command => command.Name).Order(StringComparer.Ordinal));
        var parsed = Webhooks().Parse("destinations add --url https://hook.example --ip 10.0.0.7");
        Assert.Empty(parsed.Errors);
    }

    [Fact]
    public void PublicOriginBuildsPublicRuleWithoutPins()
    {
        Assert.True(WebhookDestinationCommands.TryBuildRule("https://hook.example:8443", [], true,
            out var rule, out var error), error);
        Assert.Equal(WebhookDestinationRuleKind.Public, rule!.Kind);
        Assert.Equal("hook.example", rule.Host);
        Assert.Equal(8443, rule.Port);
        Assert.Empty(rule.AllowedIpAddresses);
    }

    [Fact]
    public void InternalOriginRequiresExactIpPins()
    {
        Assert.True(WebhookDestinationCommands.TryBuildRule("http://host.internal", ["10.0.0.7"], false,
            out var rule, out var error), error);
        Assert.Equal(WebhookDestinationRuleKind.Internal, rule!.Kind);
        Assert.Equal(["10.0.0.7"], rule.AllowedIpAddresses);
    }

    [Theory]
    [InlineData("https://host.internal", null, false)]
    [InlineData("https://host.internal", "10.0.0.0/8", false)]
    [InlineData("https://host.internal", "10.0.0.7", true)]
    [InlineData("https://host.internal/path", "10.0.0.7", false)]
    [InlineData("https://user@host.internal", "10.0.0.7", false)]
    public void InvalidAddArgumentsAreRejectedLocally(string url, string? ip, bool isPublic)
    {
        Assert.False(WebhookDestinationCommands.TryBuildRule(url, ip is null ? [] : [ip], isPublic,
            out _, out var error));
        Assert.NotNull(error);
    }
}
