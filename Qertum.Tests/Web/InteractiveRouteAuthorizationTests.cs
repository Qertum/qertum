using Bunit;
using Microsoft.AspNetCore.Components;
using Qertum.Services;
using Qertum.Web.Components;
using Qertum.Web.Components.Layout;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class InteractiveRouteAuthorizationTests : IAsyncDisposable
{
    private readonly BunitContext _context = new();
    public ValueTask DisposeAsync() => _context.DisposeAsync();

    [Theory]
    [InlineData("/settings", false)]
    [InlineData("/issuers", true)]
    public void InteractiveNavigation_RefusesAPageWithoutItsDeclaredAccess(string path, bool adminOnly)
    {
        var auth = _context.AddAuthorization().SetAuthorized("viewer");
        _context.ComponentFactories.AddStub<MainLayout>(parameters => parameters.Get(layout => layout.Body)!);
        _context.ComponentFactories.AddStub<Settings>("privileged-settings");
        _context.ComponentFactories.AddStub<Qertum.Web.Components.Pages.Issuers>("privileged-issuers");
        _context.Services.GetRequiredService<NavigationManager>().NavigateTo(path);

        var cut = _context.Render<Routes>();

        cut.WaitForAssertion(() => Assert.DoesNotContain("privileged-", cut.Markup));
        if (adminOnly) auth.SetRoles("admin");
        else { auth.SetPolicies(AppPermissions.SettingsEdit); auth.SetAuthorized("viewer"); }
        cut.WaitForAssertion(() => Assert.Contains("privileged-", cut.Markup));
        if (adminOnly) auth.SetRoles();
        else { auth.SetPolicies(); auth.SetAuthorized("viewer"); }
        cut.WaitForAssertion(() => Assert.DoesNotContain("privileged-", cut.Markup));
    }
}
