using Bunit;
using Microsoft.AspNetCore.Components;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class PageChromeTests
{
    [Fact]
    public void PageHeader_RendersTheDashboardHeaderMarkup()
    {
        using var context = new BunitContext();
        var cut = context.Render<PageHeader>(p => p
            .Add(c => c.Heading, "Certificate <em>Templates</em>")
            .Add(c => c.Subtitle, "Define profiles.")
            .Add(c => c.Actions, "<a href=\"/new\" class=\"btn\">New</a>"));

        Assert.Equal("Define profiles.", cut.Find("p.dashboard-subtitle").TextContent);
        Assert.Equal("Templates", cut.Find(".dashboard-header-row h1 em").TextContent);
        Assert.NotEmpty(cut.FindAll(".dashboard-header-row > a.btn"));
    }

    [Fact]
    public void PageHeader_OmitsSubtitleAndActionsWhenNotGiven()
    {
        using var context = new BunitContext();
        var cut = context.Render<PageHeader>(p => p.Add(c => c.Heading, "Audit <em>Log</em>"));

        Assert.Empty(cut.FindAll(".dashboard-subtitle"));
        Assert.Single(cut.FindAll(".dashboard-header-row > *"));
    }

    [Theory]
    [InlineData("success", "bi-check-circle-fill")]
    [InlineData("danger", "bi-exclamation-triangle-fill")]
    public void Notification_ShowsTheTypeAndIcon(string type, string icon)
    {
        using var context = new BunitContext();
        var cut = context.Render<Notification>(p => p.Add(c => c.Message, "Saved").Add(c => c.Type, type));

        Assert.Contains($"alert-{type}", cut.Find(".alert").ClassList);
        Assert.NotEmpty(cut.FindAll($".alert .{icon}"));
        Assert.Contains("Saved", cut.Find(".alert").TextContent);
        Assert.Equal("notification", cut.Find(".alert").GetAttribute("data-test"));
    }

    [Fact]
    public void Notification_RendersNothingForAnEmptyMessageAndDismissCallsBack()
    {
        using var context = new BunitContext();
        var empty = context.Render<Notification>(p => p.Add(c => c.Message, " "));
        Assert.Empty(empty.FindAll(".alert"));

        var dismissed = 0;
        var cut = context.Render<Notification>(p => p
            .Add(c => c.Message, "Saved")
            .Add(c => c.OnDismiss, EventCallback.Factory.Create(this, () => dismissed++)));
        cut.Find("button.btn-close").Click();
        Assert.Equal(1, dismissed);
    }

    [Fact]
    public void LoadingAndEmptyStates_RenderTheExistingMarkup()
    {
        using var context = new BunitContext();
        var loading = context.Render<LoadingState>(p => p.Add(c => c.Text, "Loading templates…"));
        Assert.Equal("Loading templates…", loading.Find(".loading-text").TextContent);
        Assert.NotEmpty(loading.FindAll(".spinner-ring"));

        var empty = context.Render<EmptyState>(p => p
            .Add(c => c.Icon, "bi-file-earmark-code").Add(c => c.Title, "No templates yet")
            .Add(c => c.Message, "Create your first.").AddChildContent("<a class=\"btn\">New</a>"));
        Assert.Equal("No templates yet", empty.Find(".empty-state-title").TextContent);
        Assert.Equal("Create your first.", empty.Find(".empty-state-message").TextContent);
        Assert.NotEmpty(empty.FindAll(".empty-state-icon .bi-file-earmark-code"));
        Assert.NotEmpty(empty.FindAll("a.btn"));
    }

    [Fact]
    public void EmptyState_ShowsAGlyphInsteadOfAnIconWhenGiven()
    {
        using var context = new BunitContext();
        var cut = context.Render<EmptyState>(p => p.Add(c => c.Glyph, "✅").Add(c => c.Title, "No denied requests"));

        Assert.Equal("✅", cut.Find(".empty-state-icon").TextContent.Trim());
        Assert.Empty(cut.FindAll(".empty-state-icon .bi"));
        Assert.Empty(cut.FindAll(".empty-state-message"));
    }
}
