using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Notices;

namespace Qertum.Tests;

public sealed class NoticeJobHandlerTests
{
    [Fact]
    public void TheSchedule_FollowsTheOptions()
    {
        var job = NoticeJobHandler.Schedule(new NoticesOptions { CheckIntervalMinutes = 15, Enabled = true });

        Assert.Equal(WellKnownJobTypes.Notices, job.JobType);
        Assert.Equal("notices", job.ConcurrencyKey);
        Assert.Equal(TimeSpan.FromMinutes(15), job.Interval);
        Assert.True(job.Enabled);
    }

    [Fact]
    public void ADisabledConfiguration_DisablesTheSchedule() =>
        Assert.False(NoticeJobHandler.Schedule(new NoticesOptions { Enabled = false }).Enabled);

    [Fact]
    public async Task Handle_RunsASweep_AndReturnsItsSummary()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);
        var handler = new NoticeJobHandler(host.Sweeper);

        var result = await handler.HandleAsync(new BackgroundJob(), TestContext.Current.CancellationToken);

        Assert.Equal("resolved=0, raised=1, queued=1, pruned=0", result);
        Assert.Equal(WellKnownJobTypes.Notices, handler.JobType);
    }
}
