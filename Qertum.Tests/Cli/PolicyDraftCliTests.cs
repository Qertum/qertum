using System.CommandLine;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class PolicyDraftCliTests
{
    private static Command Policies() => PolicyCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    [Fact]
    public void DraftSet_OffersRepeatableRequesterRole()
    {
        var set = Policies().Subcommands.Single(c => c.Name == "draft").Subcommands.Single(c => c.Name == "set");
        var option = Assert.Single(set.Options, o => o.Name == "--requester-role");

        var parsed = Policies().Parse($"draft set {Guid.NewGuid()} --requester-role ops --requester-role pki");

        Assert.Empty(parsed.Errors);
        Assert.Equal(["ops", "pki"], parsed.GetValue<string[]>(option.Name)!);
    }

    [Fact]
    public void DraftFromOptions_CarriesRoles_AndOmittedMeansEmpty()
    {
        Assert.Equal(["ops"], PolicyCommands.DraftFromOptions(null, null, null, null, ["ops"], null).AllowedRequesterRoles);
        Assert.Empty(PolicyCommands.DraftFromOptions(null, null, null, null, null, null).AllowedRequesterRoles);
    }

    [Theory]
    [InlineData("any", KeyCustodyMode.Any)]
    [InlineData("require-client-generated", KeyCustodyMode.RequireClientGenerated)]
    public void DraftSet_AcceptsKeyCustody(string value, KeyCustodyMode expected)
    {
        var parsed = Policies().Parse($"draft set {Guid.NewGuid()} --key-custody {value}");

        Assert.Empty(parsed.Errors);
        Assert.Equal(value, parsed.GetValue<string>("--key-custody"));
        Assert.Equal(expected, PolicyCommands.DraftFromOptions(null, null, null, null, null, value).KeyCustody);
    }

    [Fact]
    public void DraftSet_RefusesAnUnknownKeyCustodyValue() =>
        Assert.NotEmpty(Policies().Parse($"draft set {Guid.NewGuid()} --key-custody maybe").Errors);

    [Fact]
    public void DraftFromOptions_OmittedKeyCustody_MeansUnrestricted() =>
        Assert.Equal(KeyCustodyMode.Any, PolicyCommands.DraftFromOptions(null, null, null, null, null, null).KeyCustody);
}
