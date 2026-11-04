using System.Text.RegularExpressions;

namespace Qertum.Tests.Web;

/// <summary>
/// The web UI and the identity service run on one host in both deployments (only the port differs), and browsers
/// do not separate cookies by port. Both used ASP.NET's default session cookie name, so signing in to one replaced
/// the other's session: after the web sign-in the identity admin pages asked for the password again. Each host now
/// names its own cookie. The web host is not booted in tests (it needs a live identity provider), so the names are
/// pinned in source.
/// </summary>
public sealed partial class SessionCookieNameTests
{
    private static string Read(params string[] parts)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine([dir.FullName, .. parts]);
            if (File.Exists(path)) return File.ReadAllText(path);
        }
        throw new FileNotFoundException(Path.Combine(parts));
    }

    private static string CookieName(string program)
    {
        var names = CookieNameAssignment().Matches(program).Select(m => m.Groups[1].Value).ToList();
        return Assert.Single(names);
    }

    [Fact]
    public void TheWebAndIdentitySessionCookies_HaveTheirOwnNames()
    {
        var web = CookieName(Read("Qertum.Web", "Program.cs"));
        var identity = CookieName(Read("Qertum.IdentityService", "Program.cs"));

        Assert.NotEqual(web, identity);
        Assert.DoesNotContain(".AspNetCore.", web, StringComparison.Ordinal);
        Assert.DoesNotContain(".AspNetCore.", identity, StringComparison.Ordinal);
    }

    [GeneratedRegex(@"options\.Cookie\.Name\s*=\s*""([^""]+)""")]
    private static partial Regex CookieNameAssignment();
}
