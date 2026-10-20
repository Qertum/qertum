using Qertum.Services.Notices;

namespace Qertum.Tests;

public sealed class NoticeRulesTests
{
    private static readonly DateTime Now = new(2026, 10, 14, 12, 0, 0, DateTimeKind.Utc);
    private static readonly int[] Days = [30, 14, 7, 1];

    [Theory]
    [InlineData("30,14,7,1", new[] { 30, 14, 7, 1 })]
    [InlineData(" 30 , 14 ", new[] { 30, 14 })]
    [InlineData("7", new[] { 7 })]
    [InlineData("7,abc,3", new[] { 7, 3 })]
    [InlineData("", new int[0])]
    public void ParseExpiryDays_ReadsWholeNumbersAndSkipsTheRest(string text, int[] expected) =>
        Assert.Equal(expected, NoticeRules.ParseExpiryDays(text));

    [Theory]
    [InlineData("30,14,7,1", true)]
    [InlineData("", false)]
    [InlineData("7,7", false)]
    [InlineData("7,abc", false)]
    [InlineData("0", false)]
    [InlineData("3651", false)]
    [InlineData("1,2,3,4,5,6,7,8,9,10,11", false)]
    public void ExpiryDaysProblem_IsNullOnlyForOneToTenDistinctWholeNumbersInRange(string text, bool valid) =>
        Assert.Equal(valid, NoticeRules.ExpiryDaysProblem(text) is null);

    [Theory]
    [InlineData(45, null)]   // outside every threshold
    [InlineData(30, 30)]     // exactly on the first
    [InlineData(20, 30)]
    [InlineData(14, 14)]
    [InlineData(10, 14)]
    [InlineData(3, 7)]
    [InlineData(0.5, 1)]
    public void ExpiryStep_IsTheSmallestThresholdTheCertificateIsInside(double daysLeft, int? expected) =>
        Assert.Equal(expected, NoticeRules.ExpiryStep(Now.AddDays(daysLeft), Now, Days));

    [Fact]
    public void ExpiryStep_IgnoresTheOrderOfTheThresholds() =>
        Assert.Equal(7, NoticeRules.ExpiryStep(Now.AddDays(3), Now, [1, 30, 7, 14]));

    [Fact]
    public void ExpiryStep_IsNullForACertificateThatHasAlreadyExpired() =>
        Assert.Null(NoticeRules.ExpiryStep(Now.AddMinutes(-1), Now, Days));

    [Theory]
    [InlineData(10, 10)]
    [InlineData(9.2, 10)]
    [InlineData(0.1, 1)]
    public void DaysLeft_RoundsUpToWholeDays(double days, int expected) =>
        Assert.Equal(expected, NoticeRules.DaysLeft(Now.AddDays(days), Now));

    [Theory]
    [InlineData(-6.9, false)]
    [InlineData(-7.1, true)]
    [InlineData(5, false)]
    public void ExpiredPastGrace_IsTrueOnlyAfterTheGraceDays(double validToOffsetDays, bool expected) =>
        Assert.Equal(expected, NoticeRules.ExpiredPastGrace(Now.AddDays(validToOffsetDays), Now));

    [Theory]
    [InlineData(23.9, false)]
    [InlineData(24, true)]
    [InlineData(48, true)]
    public void EscalationDue_IsTrueOnceTheGapHasPassed(double hoursSinceRaised, bool expected) =>
        Assert.Equal(expected, NoticeRules.EscalationDue(Now.AddHours(-hoursSinceRaised), Now, 24));

    [Fact]
    public void Check_AcceptsTheDefaults() =>
        Assert.Null(NoticeRules.Check(new NoticesOptions()));

    [Theory]
    [InlineData(0)]
    [InlineData(1441)]
    public void Check_RefusesAnIntervalOutsideOneMinuteToADay(int minutes) =>
        Assert.NotNull(NoticeRules.Check(new NoticesOptions { CheckIntervalMinutes = minutes }));

    [Theory]
    [InlineData("")]
    [InlineData("7,7")]
    [InlineData("1,2,3,4,5,6,7,8,9,10,11")]
    [InlineData("0")]
    [InlineData("3651")]
    [InlineData("seven")]
    public void Check_RefusesBadThresholds(string days) =>
        Assert.NotNull(NoticeRules.Check(new NoticesOptions { ExpiryDays = days }));

    [Theory]
    [InlineData(0)]
    [InlineData(721)]
    public void Check_RefusesAnEscalationGapOutsideOneToSevenHundredTwentyHours(int hours) =>
        Assert.NotNull(NoticeRules.Check(new NoticesOptions { EscalationAfterHours = hours }));

    [Theory]
    [InlineData(0)]
    [InlineData(3651)]
    public void Check_RefusesARetentionOutsideOneToThreeThousandSixHundredFiftyDays(int days) =>
        Assert.NotNull(NoticeRules.Check(new NoticesOptions { RetentionDays = days }));
}
