using Microsoft.AspNetCore.Authorization;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// Pages used to gate on the admin role even where the API accepts settings.edit, so a deployment
/// that granted settings.edit to its own role could use the API but not the pages.
/// </summary>
public sealed class PagePolicyGatingTests
{
    private static AuthorizeAttribute Single(Type page) =>
        Assert.Single(page.GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true).Cast<AuthorizeAttribute>());

    [Theory]
    [InlineData(typeof(Settings))]
    [InlineData(typeof(Templates))]
    [InlineData(typeof(TemplateEditor))]
    [InlineData(typeof(Qertum.Web.Components.Pages.Webhooks))]
    [InlineData(typeof(Onboarding))]
    [InlineData(typeof(AcmeOrders))]
    [InlineData(typeof(AcmeOrderView))]
    [InlineData(typeof(EstCredentialActivity))]
    public void SettingsPages_GateOnSettingsEdit(Type page)
    {
        var attribute = Single(page);
        Assert.Equal(AppPermissions.SettingsEdit, attribute.Policy);
        Assert.Null(attribute.Roles);
    }

    [Theory]
    [InlineData(typeof(AuditLog))]
    [InlineData(typeof(RolePermissions))]
    [InlineData(typeof(Qertum.Web.Components.Pages.Issuers))]
    [InlineData(typeof(PqcExceptions))]
    public void AdminOnlyApis_KeepTheAdminRole(Type page)
        => Assert.Equal("admin", Single(page).Roles);

    [Fact]
    public void TheApprovalsPage_NeedsOnlyASignIn_BecauseEveryoneSeesTheirOwnRequests()
    {
        var attribute = Single(typeof(ApprovalQueue));
        Assert.Null(attribute.Policy);
        Assert.Null(attribute.Roles);
    }

    [Fact]
    public void WebhookDestinationPolicyPanel_IsVisibleOnlyInsideAdminViewOnSettings()
    {
        Assert.Matches("(?s)<AuthorizeView Roles=\"admin\">\\s*<WebhookDestinationPolicyPanel\\s*/>\\s*</AuthorizeView>",
            PageSource("Settings.razor"));
        Assert.DoesNotContain("<WebhookDestinationPolicyPanel", PageSource("Webhooks.razor"), StringComparison.Ordinal);
    }

    [Fact]
    public void TheMigrationNavLink_IsShownToCertificatesViewHolders()
    {
        var nav = File.ReadAllText(Path.Combine(RepoRoot(), "Qertum.Web", "Components", "Layout", "NavMenu.razor"));

        Assert.Matches("(?s)<AuthorizeView Policy=\"@AppPermissions\\.CertificatesView\">.*?href=\"pqc-migration\"", nav);
    }

    private static string RepoRoot()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "Qertum.sln")))
            root = root.Parent;
        Assert.NotNull(root);
        return root.FullName;
    }

    private static string PageSource(string fileName) =>
        File.ReadAllText(Path.Combine(RepoRoot(), "Qertum.Web", "Components", "Pages", fileName));
}
