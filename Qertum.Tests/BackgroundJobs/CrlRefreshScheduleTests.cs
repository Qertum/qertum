using Qertum.QueueConsumer;

namespace Qertum.Tests.BackgroundJobs;

public sealed class CrlRefreshScheduleTests
{
    private static readonly DateTime Now = new(2026, 9, 25, 20, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void IsDue_WithNoBase_IsTrue() => Assert.True(CrlRefreshSchedule.IsDue(null, 24, 0.5, Now));

    [Fact]
    public void IsDue_AtTheThreshold_IsTrue() => Assert.True(CrlRefreshSchedule.IsDue(Now.AddHours(-12), 24, 0.5, Now));

    [Fact]
    public void IsDue_JustBelowTheThreshold_IsFalse()
        => Assert.False(CrlRefreshSchedule.IsDue(Now.AddHours(-12).AddSeconds(1), 24, 0.5, Now));

    [Fact]
    public void IsDue_WithABaseInTheFuture_IsFalse() => Assert.False(CrlRefreshSchedule.IsDue(Now.AddHours(3), 24, 0.5, Now));

    [Theory]
    [InlineData(0)]
    [InlineData(-4)]
    public void Threshold_TreatsANonPositiveValidityAs24Hours(int validityHours)
    {
        Assert.Equal(TimeSpan.FromHours(12), CrlRefreshSchedule.Threshold(validityHours, 0.5));
        Assert.False(CrlRefreshSchedule.IsDue(Now.AddHours(-1), validityHours, 0.5, Now));
    }

    [Fact]
    public void Describe_NamesTheAgeAndThreshold()
    {
        Assert.Equal("base age 13.0 h >= 12.0 h", CrlRefreshSchedule.Describe(Now.AddHours(-13), 24, 0.5, Now));
        Assert.Equal("no base CRL published yet", CrlRefreshSchedule.Describe(null, 24, 0.5, Now));
    }
}
