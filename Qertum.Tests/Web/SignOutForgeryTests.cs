namespace Qertum.Tests.Web;

/// <summary>
/// Signing out was a GET, so any site could end a user's session with a link or an image (the session cookie is
/// SameSite=Lax and goes along with a top-level navigation). It is now a POST that needs the antiforgery token the
/// menu's form carries. The web host is not booted in tests (it needs a live identity provider), so the wiring is
/// pinned here and exercised end to end by the browser check, which signs out through the menu.
/// </summary>
public sealed class SignOutForgeryTests
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

    [Fact]
    public void SignOut_IsAPostThatRequiresTheAntiforgeryToken()
    {
        var program = Read("Qertum.Web", "Program.cs");

        Assert.DoesNotContain("MapGet(\"/signout\"", program);
        var post = program.IndexOf("MapPost(\"/signout\"", StringComparison.Ordinal);
        Assert.True(post >= 0, "the sign-out endpoint is missing");
        Assert.Contains("RequireAntiforgeryTokenAttribute", program[post..Math.Min(program.Length, post + 500)]);
    }

    [Fact]
    public void TheMenu_SignsOutWithAFormCarryingTheToken()
    {
        var layout = Read("Qertum.Web", "Components", "Layout", "MainLayout.razor");

        Assert.DoesNotContain("href=\"/signout\"", layout);
        var form = layout.IndexOf("action=\"/signout\"", StringComparison.Ordinal);
        Assert.True(form >= 0, "the sign-out form is missing");
        Assert.Contains("method=\"post\"", layout[(form - 80)..form]);
        Assert.Contains("<AntiforgeryToken", layout[form..(form + 300)]);
    }
}
