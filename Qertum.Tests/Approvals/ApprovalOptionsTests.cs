using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.Services.Approvals;

namespace Qertum.Tests.Approvals;

public sealed class ApprovalOptionsTests
{
    private static ApprovalOptions Resolve(params (string Key, string Value)[] overrides)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(overrides.ToDictionary(o => $"Approvals:{o.Key}", o => (string?)o.Value))
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(config);
        services.AddApprovals();
        return services.BuildServiceProvider().GetRequiredService<IOptions<ApprovalOptions>>().Value;
    }

    [Fact]
    public void Defaults_AreTheDocumentedOnes()
    {
        var options = Resolve();
        Assert.Equal(15, options.GrantWindowMinutes);
        Assert.Equal(24, options.RequestTtlHours);
        Assert.Equal(365, options.RetentionDays);
    }

    [Theory]
    [InlineData("GrantWindowMinutes", "1")]
    [InlineData("GrantWindowMinutes", "1440")]
    [InlineData("RequestTtlHours", "1")]
    [InlineData("RequestTtlHours", "168")]
    [InlineData("RetentionDays", "1")]
    [InlineData("RetentionDays", "3650")]
    public void LimitValues_AreAccepted(string key, string value) => Resolve((key, value));

    [Theory]
    [InlineData("GrantWindowMinutes", "0")]
    [InlineData("GrantWindowMinutes", "1441")]
    [InlineData("RequestTtlHours", "0")]
    [InlineData("RequestTtlHours", "169")]
    [InlineData("RetentionDays", "0")]
    [InlineData("RetentionDays", "3651")]
    public void OutOfRangeValues_AreRefused(string key, string value) =>
        Assert.Throws<OptionsValidationException>(() => Resolve((key, value)));
}
