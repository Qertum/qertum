using Qertum.Services.Notices;
using Qertum.Services;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Qertum.ApiService;
using Qertum.QueueConsumer;
using Qertum.Services.Webhooks;
using Qertum.Services.Acme;
using Qertum.Services.Est;
using Qertum.Web.Auth;

namespace Qertum.Tests.Configuration;

/// <summary>
/// Every configuration section is bound to an options class validated at startup. A bad value used to
/// be read ad hoc with <c>GetValue</c> on first use — a zero rate-limit window or a negative delay
/// surfaced as a runtime failure, or silently as a spin loop, long after the host reported healthy.
/// </summary>
public sealed class OptionsValidationTests
{
    public static TheoryData<string, string, Type, Action<IServiceCollection>> InvalidValues => new()
    {
        { "RateLimiting:PermitLimit", "0", typeof(ApiRateLimitOptions), s => s.AddApiRateLimiting() },
        { "RateLimiting:WindowSeconds", "0", typeof(ApiRateLimitOptions), s => s.AddApiRateLimiting() },
        { "RateLimiting:QueueLimit", "-1", typeof(ApiRateLimitOptions), s => s.AddApiRateLimiting() },
        { "Acme:RateLimits:PollingPermitLimit", "0", typeof(AcmeRateLimitOptions), s => s.AddAcmeRateLimiting() },
        { "Acme:RateLimits:WriteWindowSeconds", "0", typeof(AcmeRateLimitOptions), s => s.AddAcmeRateLimiting() },
        { "Est:RateLimits:PermitLimit", "0", typeof(EstOptions), s => s.AddEstRateLimiting() },
        { "Est:RateLimits:WindowSeconds", "0", typeof(EstOptions), s => s.AddEstRateLimiting() },
        { "QueueConsumer:IdleDelayMs", "0", typeof(QueueConsumerOptions), s => s.AddQueueConsumerOptions() },
        { "QueueConsumer:ProcessingDelayMs", "-1", typeof(QueueConsumerOptions), s => s.AddQueueConsumerOptions() },
        { "QueueConsumer:ErrorDelayMs", "0", typeof(QueueConsumerOptions), s => s.AddQueueConsumerOptions() },
        { "Webhook:DeliveryPollIntervalSeconds", "0", typeof(WebhookDeliveryOptions), s => s.AddQueueConsumerOptions() },
        { "WebhookDestinationPolicy:Rules:0:Host", "*.invalid", typeof(WebhookDestinationPolicyOptions), s => s.AddWebhookDestinationPolicyOptions() },
        { "WebhookDestinationPolicy:Rules:0:AllowedIpAddresses:0", "169.254.169.254", typeof(WebhookDestinationPolicyOptions), s => s.AddWebhookDestinationPolicyOptions() },
        { "AutoRenewal:CheckIntervalHours", "0", typeof(AutoRenewalOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:PollIntervalSeconds", "0", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:MaxAttempts", "0", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:RetryBaseDelaySeconds", "0", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:MaxRetryDelaySeconds", "10", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:RetentionDays", "0", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "BackgroundJobs:ProcessingTimeoutMinutes", "0", typeof(BackgroundJobOptions), s => s.AddQueueConsumerOptions() },
        { "CrlRefresh:CheckIntervalMinutes", "0", typeof(CrlRefreshOptions), s => s.AddQueueConsumerOptions() },
        { "CrlRefresh:RefreshAtFraction", "1", typeof(CrlRefreshOptions), s => s.AddQueueConsumerOptions() },
        { "CrlRefresh:RefreshAtFraction", "0", typeof(CrlRefreshOptions), s => s.AddQueueConsumerOptions() },
        { "Acme:ExpiryCleanup:Interval", "00:00:30", typeof(AcmeExpiryCleanupOptions), s => s.AddQueueConsumerOptions() },
        { "Acme:ExpiryCleanup:Retention", "-1.00:00:00", typeof(AcmeExpiryCleanupOptions), s => s.AddQueueConsumerOptions() },
        { "Acme:ExpiryCleanup:BatchSize", "0", typeof(AcmeExpiryCleanupOptions), s => s.AddQueueConsumerOptions() },
        { "PqcExceptions:MaxDays", "0", typeof(PqcExceptionOptions), s => s.AddPqcExceptionOptions() },
        { "PqcExceptions:MaxDays", "3651", typeof(PqcExceptionOptions), s => s.AddPqcExceptionOptions() },
        { "Notices:CheckIntervalMinutes", "0", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:CheckIntervalMinutes", "1441", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:EscalationAfterHours", "0", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:RetentionDays", "0", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:ExpiryDays", "0", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:ExpiryDays", "7,7", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "Notices:ExpiryDays", "seven", typeof(NoticesOptions), s => s.AddQueueConsumerOptions() },
        { "AuditLog:Checkpoint:IntervalMinutes", "0", typeof(AuditLogOptions), s => s.AddQueueConsumerOptions() },
        { "AuditLog:Checkpoint:IntervalMinutes", "1441", typeof(AuditLogOptions), s => s.AddQueueConsumerOptions() },
    };

    [Theory]
    [MemberData(nameof(InvalidValues))]
    public void AnInvalidValue_FailsValidation(string key, string value, Type optionsType, Action<IServiceCollection> register)
    {
        using var provider = Build(register, new Dictionary<string, string?> { [key] = value });

        var ex = Assert.ThrowsAny<Exception>(() => Resolve(provider, optionsType));
        Assert.IsType<OptionsValidationException>(ex is TargetInvocationException tie ? tie.InnerException : ex);
    }

    [Theory]
    [MemberData(nameof(InvalidValues))]
    public void TheShippedDefaults_PassValidation(string key, string value, Type optionsType, Action<IServiceCollection> register)
    {
        _ = key;
        _ = value;
        using var provider = Build(register, new Dictionary<string, string?>());

        Assert.NotNull(Resolve(provider, optionsType));
    }

    private static ServiceProvider Build(Action<IServiceCollection> register, Dictionary<string, string?> values)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        register(services);
        return services.BuildServiceProvider();
    }

    private static object Resolve(IServiceProvider provider, Type optionsType)
    {
        var options = provider.GetRequiredService(typeof(IOptions<>).MakeGenericType(optionsType));
        return options.GetType().GetProperty(nameof(IOptions<object>.Value))!.GetValue(options)!;
    }
}

/// <summary>
/// Every key an options class reads ships in its host's appsettings.json at its default, so a setting
/// can be found without reading the source. <c>AutoRenewal:CheckIntervalHours</c> once existed only in
/// a <c>GetValue</c> call.
/// </summary>
public sealed class ShippedConfigurationTests
{
    public static TheoryData<string, string, Type> Sections => new()
    {
        { "Qertum.ApiService", ApiRateLimitOptions.SectionName, typeof(ApiRateLimitOptions) },
        { "Qertum.AcmeService", AcmeRateLimitOptions.SectionName, typeof(AcmeRateLimitOptions) },
        { "Qertum.EstService", EstOptions.SectionName, typeof(EstOptions) },
        { "Qertum.QueueConsumer", QueueConsumerOptions.SectionName, typeof(QueueConsumerOptions) },
        { "Qertum.QueueConsumer", WebhookDeliveryOptions.SectionName, typeof(WebhookDeliveryOptions) },
        { "Qertum.ApiService", WebhookDestinationPolicyOptions.SectionName, typeof(WebhookDestinationPolicyOptions) },
        { "Qertum.ApiService", PqcExceptionOptions.SectionName, typeof(PqcExceptionOptions) },
        { "Qertum.QueueConsumer", AutoRenewalOptions.SectionName, typeof(AutoRenewalOptions) },
        { "Qertum.QueueConsumer", BackgroundJobOptions.SectionName, typeof(BackgroundJobOptions) },
        { "Qertum.QueueConsumer", CrlRefreshOptions.SectionName, typeof(CrlRefreshOptions) },
        { "Qertum.QueueConsumer", AcmeExpiryCleanupOptions.SectionName, typeof(AcmeExpiryCleanupOptions) },
        { "Qertum.QueueConsumer", NoticesOptions.SectionName, typeof(NoticesOptions) },
        { "Qertum.QueueConsumer", AuditLogOptions.SectionName, typeof(AuditLogOptions) },
        { "Qertum.ApiService", AuditLogOptions.SectionName, typeof(AuditLogOptions) },
        { "Qertum.ApiService", Qertum.Services.Approvals.ApprovalOptions.SectionName, typeof(Qertum.Services.Approvals.ApprovalOptions) },
        { "Qertum.QueueConsumer", Qertum.Services.Approvals.ApprovalOptions.SectionName, typeof(Qertum.Services.Approvals.ApprovalOptions) },

        { "Qertum.Web", OidcMetadataOptions.SectionName, typeof(OidcMetadataOptions) },
        { "Qertum.IdentityService", "IdentityService", typeof(Qertum.IdentityService.Configuration.IdentityServiceOptions) },
    };

    [Theory]
    [MemberData(nameof(Sections))]
    public void EveryOptionsPropertyShipsInAppSettings(string project, string section, Type optionsType)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(FindRepoRoot(), project, "appsettings.json")));
        var node = section.Split(':').Aggregate(doc.RootElement, (element, name) =>
        {
            Assert.True(element.TryGetProperty(name, out var child), $"{project}/appsettings.json has no '{section}' section.");
            return child;
        });

        foreach (var missing in MissingKeys(node, optionsType, section))
            Assert.Fail($"{project}/appsettings.json does not ship '{missing}'.");
    }

    private static IEnumerable<string> MissingKeys(JsonElement node, Type type, string path)
    {
        foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.CanWrite))
        {
            var key = $"{path}:{property.Name}";
            if (NeverShipped.Contains(key)) continue;
            if (!node.TryGetProperty(property.Name, out var child))
            {
                yield return key;
                continue;
            }
            if (property.PropertyType.IsClass && property.PropertyType != typeof(string) && !property.PropertyType.IsArray
                && child.ValueKind == JsonValueKind.Object)
                foreach (var nested in MissingKeys(child, property.PropertyType, key))
                    yield return nested;
        }
    }

    // Secrets never go into a checked-in file; they come from user secrets, the environment or Aspire.
    private static readonly HashSet<string> NeverShipped = new(StringComparer.Ordinal)
    {
        "IdentityService:ApiClientSecret",
        "IdentityService:SeedAdminPassword",
    };

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
