using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// The instruments an operator alerts on. Names and tags are the contract: renaming one silently
/// breaks someone's alert rule, so these tests pin them.
/// </summary>
public sealed class OperationsMetricsTests
{
    [Fact]
    public void AddQueueConsumerMetrics_RegistersOperationsMetricsAsASingleton()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMetrics();
        services.AddQueueConsumerMetrics();
        using var provider = services.BuildServiceProvider();

        Assert.Same(provider.GetRequiredService<OperationsMetrics>(), provider.GetRequiredService<OperationsMetrics>());
    }
}
