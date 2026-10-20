using Qertum.Cli.Commands;

namespace Qertum.Tests.Cli;

/// <summary>
/// A MAC key is base64url, so one in 64 starts with '-'. certbot's argument parser reads a separate word that starts
/// with '-' as an option and answers "expected one argument", so every certbot command Qertum prints uses the
/// <c>--eab-hmac-key=KEY</c> form. The interop matrix found this with a real certbot.
/// </summary>
public sealed class AcmeEabOutputTests
{
    [Theory]
    [InlineData("-leading-dash_KEY")]
    [InlineData("plainKey123")]
    public void TheCertbotCommand_AttachesTheMacKeyWithAnEqualsSign(string macKey)
    {
        var lines = AcmeCommands.CertbotRegisterLines("kid-1", macKey);

        Assert.Contains(lines, l => l.Contains($"--eab-hmac-key={macKey}", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains("--eab-hmac-key ", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains("--eab-kid kid-1", StringComparison.Ordinal));
    }

    [Fact]
    public void TheSettingsPage_PrintsTheSameForm()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "Qertum.sln")))
            root = root.Parent;
        Assert.NotNull(root);
        var settings = File.ReadAllText(Path.Combine(root.FullName, "Qertum.Web", "Components", "Pages", "Settings.razor"));

        Assert.Contains("--eab-hmac-key=@issuedKey.MacKey", settings, StringComparison.Ordinal);
        Assert.DoesNotContain("--eab-hmac-key @issuedKey.MacKey", settings, StringComparison.Ordinal);
    }
}
