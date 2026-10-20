using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Services.BulkOperations;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkOptionsTests
{
    private static BulkOperationsOptions Resolve(params (string Key, string Value)[] overrides)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(overrides.ToDictionary(o => $"BulkOperations:{o.Key}", o => (string?)o.Value))
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddBulkOperations();
        return services.BuildServiceProvider().GetRequiredService<IOptions<BulkOperationsOptions>>().Value;
    }

    [Fact]
    public void Defaults_AreTheDocumentedOnes()
    {
        var options = Resolve();
        Assert.Equal(10_000, options.MaxItems);
        Assert.Equal(60, options.PreviewTtlMinutes);
        Assert.Equal(365, options.RetentionDays);
    }

    [Theory]
    [InlineData("MaxItems", "0")]
    [InlineData("MaxItems", "100001")]
    [InlineData("PreviewTtlMinutes", "0")]
    [InlineData("PreviewTtlMinutes", "1441")]
    [InlineData("RetentionDays", "0")]
    public void OutOfRangeValues_AreRefused(string key, string value)
    {
        Assert.Throws<OptionsValidationException>(() => Resolve((key, value)));
    }
}
