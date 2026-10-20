using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Qertum.Services.Approvals;

/// <summary>The <c>Approvals</c> section: time limits for two-person approval.</summary>
public sealed class ApprovalOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Approvals";

    /// <summary>Minutes an approved grant stays usable.</summary>
    public int GrantWindowMinutes { get; set; } = 15;

    /// <summary>Hours a request may wait for a decision before it expires.</summary>
    public int RequestTtlHours { get; set; } = 24;

    /// <summary>Days a finished request is kept.</summary>
    public int RetentionDays { get; set; } = 365;
}

/// <summary>Registration of the approval services, shared by ApiService and QueueConsumer.</summary>
public static class ApprovalServiceCollectionExtensions
{
    /// <summary>Binds and validates <see cref="ApprovalOptions"/> and registers the approval service.</summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The same collection.</returns>
    public static IServiceCollection AddApprovals(this IServiceCollection services)
    {
        services.AddOptions<ApprovalOptions>()
            .BindConfiguration(ApprovalOptions.SectionName)
            .Validate(o => o.GrantWindowMinutes is >= 1 and <= 1440, "Approvals:GrantWindowMinutes must be between 1 and 1440.")
            .Validate(o => o.RequestTtlHours is >= 1 and <= 168, "Approvals:RequestTtlHours must be between 1 and 168.")
            .Validate(o => o.RetentionDays is >= 1 and <= 3650, "Approvals:RetentionDays must be between 1 and 3650.")
            .ValidateOnStart();
        services.TryAddScoped<IApprovalService, ApprovalService>();
        return services;
    }
}
