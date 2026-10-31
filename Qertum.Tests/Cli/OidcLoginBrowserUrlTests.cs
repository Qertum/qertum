using Qertum.Cli.Auth;

namespace Qertum.Tests.Cli;

/// <summary>
/// <c>qca auth login</c> opens the identity provider's verification URL with the shell. Only a web
/// address may reach it: on Windows a file path, UNC share or custom protocol would be opened too.
/// </summary>
public sealed class OidcLoginBrowserUrlTests
{
    [Theory]
    [InlineData("https://idp.example.com/device?user_code=ABCD")]
    [InlineData("http://localhost:5000/connect/verify")]
    public void AWebAddressIsOpened(string url) => Assert.True(OidcLogin.IsBrowserUrl(url));

    [Theory]
    [InlineData(@"C:\Windows\System32\calc.exe")]
    [InlineData(@"\\attacker\share\run.exe")]
    [InlineData("file:///etc/passwd")]
    [InlineData("ms-settings:privacy")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/connect/verify")]
    [InlineData("")]
    [InlineData(null)]
    public void AnythingElseIsOnlyPrinted(string? url) => Assert.False(OidcLogin.IsBrowserUrl(url));
}
