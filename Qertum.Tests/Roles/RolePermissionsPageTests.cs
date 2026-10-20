using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Roles;

public sealed class RolePermissionsPageTests
{
    private static IRenderedComponent<RolePermissions> Render(RolesPageTestHost host)
    {
        var cut = host.Context.Render<RolePermissions>();
        cut.WaitForElement("tr[data-role='ops']");
        return cut;
    }

    [Fact]
    public async Task AdminRow_IsCheckedAndLocked()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        var boxes = cut.FindAll("tr[data-role='admin'] input[type='checkbox']");
        Assert.Equal(AppPermissions.All.Count, boxes.Count);
        Assert.All(boxes, b =>
        {
            Assert.True(b.HasAttribute("disabled"));
            Assert.True(b.HasAttribute("checked"));
        });
    }

    [Fact]
    public async Task Toggle_ShowsSaveAndRevert_RevertRestores()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);
        Assert.Empty(cut.FindAll("tr[data-role='ops'] [data-action='save']"));

        cut.Find($"tr[data-role='ops'] input[data-permission='{AppPermissions.CertificatesManage}']").Change(true);
        Assert.NotNull(cut.Find("tr[data-role='ops'] [data-action='save']"));

        cut.Find("tr[data-role='ops'] [data-action='revert']").Click();
        Assert.Empty(cut.FindAll("tr[data-role='ops'] [data-action='save']"));
        Assert.False(cut.Find($"tr[data-role='ops'] input[data-permission='{AppPermissions.CertificatesManage}']").HasAttribute("checked"));
    }

    [Fact]
    public async Task Save_SendsCatalogOrderedPermissions_AndReportsChange()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        cut.Find($"tr[data-role='ops'] input[data-permission='{AppPermissions.CertificatesManage}']").Change(true);
        cut.Find("tr[data-role='ops'] [data-action='save']").Click();

        cut.WaitForAssertion(() => Assert.Single(host.Api.Puts));
        // Tuple equality would compare the two arrays by reference, so assert the parts separately.
        Assert.Equal("ops", host.Api.Puts[0].Role);
        Assert.Equal([AppPermissions.CertificatesView, AppPermissions.CertificatesManage], host.Api.Puts[0].Permissions);
        cut.WaitForAssertion(() => Assert.Contains("ops", cut.Find("[data-test='notification']").TextContent));
    }

    [Fact]
    public async Task RemoveAll_NeedsConfirmation()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        cut.Find("tr[data-role='ops'] [data-action='remove']").Click();
        Assert.Empty(host.Api.Puts);
        cut.Find("tr[data-role='ops'] [data-action='confirm-remove']").Click();

        cut.WaitForAssertion(() => Assert.Equal(("ops", 0), (host.Api.Puts.Single().Role, host.Api.Puts.Single().Permissions.Count)));
    }

    [Fact]
    public async Task AddRole_DisabledUntilPermissionChosen_AndInvalidNameShowsRule()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        cut.Find("#new-role").Input("new team");
        Assert.True(cut.Find("[data-action='add']").HasAttribute("disabled"));

        cut.Find($"tr[data-role='new'] input[data-permission='{AppPermissions.CertificatesView}']").Change(true);
        Assert.False(cut.Find("[data-action='add']").HasAttribute("disabled"));

        cut.Find("#new-role").Input("bad/name");
        cut.Find("[data-action='add']").Click();
        Assert.Contains("'/'", cut.Find("[data-test='new-role-error']").TextContent);
        Assert.Empty(host.Api.Puts);

        cut.Find("#new-role").Input("OPS");
        cut.Find("[data-action='add']").Click();
        Assert.Contains("already exists", cut.Find("[data-test='new-role-error']").TextContent);
        Assert.Empty(host.Api.Puts);
    }

    [Fact]
    public async Task ServerProblem_IsShown()
    {
        await using var host = new RolesPageTestHost();
        host.Api.PutProblemDetail = "Unknown permissions: nope";
        var cut = Render(host);

        cut.Find($"tr[data-role='ops'] input[data-permission='{AppPermissions.CertificatesManage}']").Change(true);
        cut.Find("tr[data-role='ops'] [data-action='save']").Click();

        cut.WaitForAssertion(() => Assert.Contains("Unknown permissions: nope", cut.Find("[data-test='notification']").TextContent));
    }

    [Fact]
    public async Task LoadFailure_ShowsErrorNotEmptyMatrix()
    {
        await using var host = new RolesPageTestHost();
        host.Api.FailOverview = true;
        var cut = host.Context.Render<RolePermissions>();

        cut.WaitForElement("[data-test='load-error']");
        Assert.Empty(cut.FindAll("table"));
    }

    [Fact]
    public async Task DriftBadges_AndGrantPrefillsAddRole()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        Assert.NotNull(cut.Find("tr[data-role='ghost'] [data-status='never-seen']"));
        Assert.NotNull(cut.Find("tr[data-role='stale'] [data-status='stale']"));
        Assert.NotNull(cut.Find("tr[data-role='ops'] [data-status='seen']"));

        cut.Find("[data-action='grant'][data-role-name='auditors']").Click();
        Assert.Equal("auditors", cut.Find("#new-role").GetAttribute("value"));
    }

    [Fact]
    public async Task Rename_NeedsConfirmation_AndSendsTheNewName()
    {
        await using var host = new RolesPageTestHost();
        var cut = Render(host);

        cut.Find("tr[data-role='ops'] [data-action='rename']").Click();
        Assert.Empty(host.Api.Renames);

        cut.Find("tr[data-role='ops'] input[data-test='rename-input']").Input("platform");
        cut.Find("tr[data-role='ops'] [data-action='confirm-rename']").Click();

        cut.WaitForAssertion(() => Assert.Equal(("ops", "platform"), host.Api.Renames.Single()));
        cut.WaitForAssertion(() => Assert.Contains("platform", cut.Find("[data-test='notification']").TextContent));
    }

    [Fact]
    public async Task Rename_Conflict_IsShown()
    {
        await using var host = new RolesPageTestHost();
        host.Api.RenameProblemDetail = "platform already has grants.";
        var cut = Render(host);

        cut.Find("tr[data-role='ops'] [data-action='rename']").Click();
        cut.Find("tr[data-role='ops'] input[data-test='rename-input']").Input("platform");
        cut.Find("tr[data-role='ops'] [data-action='confirm-rename']").Click();

        cut.WaitForAssertion(() => Assert.Contains("already has grants", cut.Find("[data-test='notification']").TextContent));
    }
}
