using Qertum.Cli;
using Qertum.Cli.Auth;

namespace Qertum.Tests.Cli;

public sealed class LoginStepUpTests
{
    [Fact]
    public void ThePlainDeviceRequest_HasOnlyTheClientAndScope()
    {
        var fields = OidcLogin.DeviceRequestFields(null, null);

        Assert.Equal(["client_id", "scope"], fields.Select(f => f.Key));
    }

    [Fact]
    public void StepUpParameters_AreAddedToTheDeviceRequest_WhenGiven()
    {
        var fields = OidcLogin.DeviceRequestFields("mfa", 300).ToDictionary(f => f.Key, f => f.Value);

        Assert.Equal("mfa", fields["acr_values"]);
        Assert.Equal("300", fields["max_age"]);
    }

    [Fact]
    public void LoginHasTheTwoNewOptions_WithDescriptions()
    {
        var login = CliRoot.Build().Subcommands.Single(c => c.Name == "auth").Subcommands.Single(c => c.Name == "login");

        foreach (var name in new[] { "--acr-values", "--max-age" })
            Assert.False(string.IsNullOrWhiteSpace(login.Options.Single(o => o.Name == name).Description));
    }
}
