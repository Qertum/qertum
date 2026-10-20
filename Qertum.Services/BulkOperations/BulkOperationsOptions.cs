using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Qertum.Services.BulkOperations;

/// <summary>The <c>BulkOperations</c> section: limits for bulk revoke and renew.</summary>
public sealed class BulkOperationsOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "BulkOperations";

    /// <summary>Most items one operation may freeze; a larger match is refused so the operator narrows the filter.</summary>
    public int MaxItems { get; set; } = 10_000;

    /// <summary>Minutes a preview stays executable before it expires.</summary>
    public int PreviewTtlMinutes { get; set; } = 60;

    /// <summary>Days a finished operation, with its items, is kept.</summary>
    public int RetentionDays { get; set; } = 365;
}

/// <summary>Registration of the bulk operation services, shared by ApiService and QueueConsumer.</summary>
public static class BulkOperationsServiceCollectionExtensions
{
    /// <summary>Binds and validates <see cref="BulkOperationsOptions"/> and registers the bulk services.</summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same collection.</returns>
    public static IServiceCollection AddBulkOperations(this IServiceCollection services)
    {
        services.AddOptions<BulkOperationsOptions>()
            .BindConfiguration(BulkOperationsOptions.SectionName)
            .Validate(o => o.MaxItems is >= 1 and <= 100_000, "BulkOperations:MaxItems must be between 1 and 100000.")
            .Validate(o => o.PreviewTtlMinutes is >= 1 and <= 1440, "BulkOperations:PreviewTtlMinutes must be between 1 and 1440.")
            .Validate(o => o.RetentionDays is >= 1 and <= 3650, "BulkOperations:RetentionDays must be between 1 and 3650.")
            .ValidateOnStart();
        services.AddScoped<IBulkOperationService, BulkOperationService>();
        services.AddScoped<IBulkItemActions, CertificateRequestBulkItemActions>();
        services.AddScoped<BulkOperationRunner>();
        return services;
    }
}
