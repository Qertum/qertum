using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Web;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class ConfirmDialogTests
{
    private static IRenderedComponent<ConfirmDialog> Render(BunitContext context, Action<ComponentParameterCollectionBuilder<ConfirmDialog>>? configure = null)
    {
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        return context.Render<ConfirmDialog>(p =>
        {
            p.Add(c => c.Title, "Delete Template").AddChildContent("<p id=\"body\">Sure?</p>");
            p.Add(c => c.ConfirmLabel, "Delete");
            configure?.Invoke(p);
        });
    }

    [Fact]
    public void RendersTitleBodyAndBothButtons()
    {
        using var context = new BunitContext();
        var cut = Render(context);

        Assert.Contains("Delete Template", cut.Find(".confirm-dialog-title").TextContent);
        Assert.Equal("Sure?", cut.Find("#body").TextContent);
        Assert.Equal("Cancel", cut.Find(".confirm-dialog-actions .btn-outline-detail").TextContent.Trim());
        Assert.Equal("Delete", cut.Find(".confirm-dialog-confirm").TextContent.Trim());
        Assert.NotNull(cut.Find("[role='dialog'][aria-modal='true']"));
    }

    [Fact]
    public void ConfirmAndCancelInvokeTheirCallbacks()
    {
        using var context = new BunitContext();
        int confirmed = 0, cancelled = 0;
        var cut = Render(context, p => p
            .Add(c => c.OnConfirm, EventCallback.Factory.Create(this, () => confirmed++))
            .Add(c => c.OnCancel, EventCallback.Factory.Create(this, () => cancelled++)));

        cut.Find(".confirm-dialog-confirm").Click();
        cut.Find(".confirm-dialog-actions .btn-outline-detail").Click();

        Assert.Equal(1, confirmed);
        Assert.Equal(1, cancelled);
    }

    [Fact]
    public void EscapeCancelsAndDoesNotConfirm()
    {
        using var context = new BunitContext();
        int confirmed = 0, cancelled = 0;
        var cut = Render(context, p => p
            .Add(c => c.OnConfirm, EventCallback.Factory.Create(this, () => confirmed++))
            .Add(c => c.OnCancel, EventCallback.Factory.Create(this, () => cancelled++)));

        cut.Find(".confirm-dialog").KeyDown(new KeyboardEventArgs { Key = "Escape" });
        cut.Find(".confirm-dialog").KeyDown(new KeyboardEventArgs { Key = "Enter" });

        Assert.Equal(1, cancelled);
        Assert.Equal(0, confirmed);
    }

    [Fact]
    public void BusyDisablesBothButtonsAndShowsASpinner()
    {
        using var context = new BunitContext();
        var cut = Render(context, p => p.Add(c => c.Busy, true));

        Assert.True(cut.Find(".confirm-dialog-confirm").HasAttribute("disabled"));
        Assert.True(cut.Find(".confirm-dialog-actions .btn-outline-detail").HasAttribute("disabled"));
        Assert.NotEmpty(cut.FindAll(".confirm-dialog-confirm .spinner-border"));
    }

    [Fact]
    public void ConfirmDisabledDisablesOnlyTheConfirmButton()
    {
        using var context = new BunitContext();
        var cut = Render(context, p => p.Add(c => c.ConfirmDisabled, true));

        Assert.True(cut.Find(".confirm-dialog-confirm").HasAttribute("disabled"));
        Assert.False(cut.Find(".confirm-dialog-actions .btn-outline-detail").HasAttribute("disabled"));
    }

    [Fact]
    public void TestIdNamesTheOverlayAndBothButtons()
    {
        using var context = new BunitContext();
        var cut = Render(context, p => p.Add(c => c.TestId, "pqc-stage"));

        Assert.NotEmpty(cut.FindAll("[data-test='pqc-stage-confirm']"));
        Assert.NotEmpty(cut.FindAll("[data-test='pqc-stage-apply']"));
        Assert.NotEmpty(cut.FindAll("[data-test='pqc-stage-cancel']"));
    }

    [Fact]
    public void WithoutATestIdNoDataTestAttributeIsRendered()
    {
        using var context = new BunitContext();
        var cut = Render(context);

        Assert.Empty(cut.FindAll("[data-test]"));
    }

    [Theory]
    [InlineData(ConfirmDialogTone.Danger, "confirm-dialog-title-danger", "btn-danger-soft")]
    [InlineData(ConfirmDialogTone.Neutral, "confirm-dialog-title-neutral", "btn-primary")]
    public void ToneChoosesTheTitleAndConfirmButtonStyle(ConfirmDialogTone tone, string titleClass, string buttonClass)
    {
        using var context = new BunitContext();
        var cut = Render(context, p => p.Add(c => c.Tone, tone));

        Assert.Contains(titleClass, cut.Find(".confirm-dialog-title").ClassList);
        Assert.Contains(buttonClass, cut.Find(".confirm-dialog-confirm").ClassList);
    }
}
