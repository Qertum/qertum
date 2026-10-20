using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcReportQueryTests
{
    [Fact]
    public void Defaults_AreValid()
    {
        var query = new PqcReportQuery();

        Assert.Null(query.Validate());
        Assert.Equal((30, 1, 50), (query.ObservedDays, query.Page, query.PageSize));
    }

    [Theory]
    [InlineData(0, 1, 50)]
    [InlineData(366, 1, 50)]
    [InlineData(30, 0, 50)]
    [InlineData(30, 1, 0)]
    [InlineData(30, 1, 501)]
    public void OutOfRangeBounds_AreRefused(int days, int page, int pageSize) =>
        Assert.NotNull(new PqcReportQuery { ObservedDays = days, Page = page, PageSize = pageSize }.Validate());

    [Theory]
    [InlineData(1, 1, 1)]
    [InlineData(365, 100, 500)]
    public void TheEdgesOfTheBounds_AreAllowed(int days, int page, int pageSize) =>
        Assert.Null(new PqcReportQuery { ObservedDays = days, Page = page, PageSize = pageSize }.Validate());

    [Fact]
    public void AnUndefinedProposedStage_IsRefused() =>
        Assert.NotNull(new PqcReportQuery { ProposedStage = (PqcStage)42 }.Validate());

    [Fact]
    public void WithPage_KeepsEveryOtherField()
    {
        var query = new PqcReportQuery { TemplateTypeKey = "WebServer", ProposedStage = PqcStage.Warn, ObservedDays = 7 };

        var next = query.WithPage(3, 500);

        Assert.Equal(("WebServer", PqcStage.Warn, 7, 3, 500),
            (next.TemplateTypeKey, next.ProposedStage, next.ObservedDays, next.Page, next.PageSize));
    }

    [Fact]
    public void TheScopeNote_MakesNoReadinessCompatibilityOrSecurityClaim()
    {
        var note = PqcMigrationReportNotes.Scope;

        foreach (var word in new[] { "ready", "compatible", "secure" })
            Assert.DoesNotContain(word, note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("renewed", note, StringComparison.Ordinal);
        Assert.Contains("SignatureVerifiedWithCurrentRoot", note, StringComparison.Ordinal);
        Assert.Contains("Unknown", note, StringComparison.Ordinal);
    }

    [Fact]
    public void WithItems_ReplacesOnlyTheItems()
    {
        var report = new PqcMigrationReportResponse
        {
            CaDefaultStage = PqcStage.Warn, Withheld = ["observed"], Items = new PagedResult<PqcReportItem> { TotalCount = 9, Page = 2, PageSize = 3 }
        };

        var merged = report.WithItems(new PagedResult<PqcReportItem> { TotalCount = 9, Page = 1, PageSize = 9 });

        Assert.Equal(PqcStage.Warn, merged.CaDefaultStage);
        Assert.Equal(["observed"], merged.Withheld);
        Assert.Equal(1, merged.Items.Page);
    }
}
