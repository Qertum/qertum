using Microsoft.Extensions.DependencyInjection;

namespace Qertum.Services;

/// <summary>Bounds on PQC exceptions (<c>PqcExceptions</c> section).</summary>
public sealed class PqcExceptionOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "PqcExceptions";

    /// <summary>The longest an exception may run from the moment it is granted, in days.</summary>
    public int MaxDays { get; set; } = 365;
}

/// <summary>Registers <see cref="PqcExceptionOptions"/>.</summary>
public static class PqcExceptionOptionsRegistration
{
    /// <summary>Binds and validates <see cref="PqcExceptionOptions"/> at startup.</summary>
    public static IServiceCollection AddPqcExceptionOptions(this IServiceCollection services)
    {
        services.AddOptions<PqcExceptionOptions>()
            .BindConfiguration(PqcExceptionOptions.SectionName)
            .Validate(o => o.MaxDays is >= 1 and <= 3650, "PqcExceptions:MaxDays must be between 1 and 3650.")
            .ValidateOnStart();
        return services;
    }
}
