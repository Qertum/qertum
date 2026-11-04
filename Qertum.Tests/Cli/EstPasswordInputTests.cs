using Qertum.Cli;
using Qertum.Cli.Commands;
using Qertum.Cli.Root;

namespace Qertum.Tests.Cli;

public sealed class EstPasswordInputTests
{
    [Theory]
    [InlineData("est credentials create --username device")]
    [InlineData("est credentials create --username device --password-stdin")]
    public void CreatingACredential_DoesNotRequireAPasswordArgument(string command)
        => Assert.Empty(CliRoot.Build().Parse(command).Errors);

    [Fact]
    public void CreatingACredential_RefusesSecretsInProcessArguments()
        => Assert.NotEmpty(CliRoot.Build().Parse("est credentials create --username device --password exposed-secret").Errors);

    [Fact]
    public async Task StdinPreservesPasswordWhitespace_AndDoesNotReadAnotherLine()
    {
        using var input = new StringReader(" secret with spaces \nnext line\n");
        var password = await EstCommands.ReadPasswordAsync(true, input, new ForbiddenPrompt(), TestContext.Current.CancellationToken);

        Assert.Equal(" secret with spaces ", password);
        Assert.Equal("next line", await input.ReadLineAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task InteractiveInputUsesTheExistingHiddenPrompt()
    {
        using var input = new StringReader("must not be read");
        var password = await EstCommands.ReadPasswordAsync(false, input, new FixedPrompt(), TestContext.Current.CancellationToken);

        Assert.Equal("prompted-secret", password);
        Assert.Equal("must not be read", await input.ReadLineAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MissingStdinDoesNotInventAPassword()
    {
        using var input = new StringReader("");
        Assert.Null(await EstCommands.ReadPasswordAsync(true, input, new ForbiddenPrompt(), TestContext.Current.CancellationToken));
    }

    private sealed class ForbiddenPrompt : IPassphrasePrompt
    {
        public string Read(string prompt) => throw new InvalidOperationException("Must not prompt when reading stdin.");
    }

    private sealed class FixedPrompt : IPassphrasePrompt
    {
        public string Read(string prompt) => "prompted-secret";
    }
}
