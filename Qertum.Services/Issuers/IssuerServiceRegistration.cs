using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Issuers;

public static class IssuerServiceRegistration
{
    /// <summary>
    /// Registers <see cref="IssuerStorage"/> and <see cref="IIssuerRegistry"/>. Needs
    /// <see cref="CaDataOptions"/>, <see cref="ICertificateGenerator"/>, an <see cref="IDataProtectionProvider"/>
    /// and an <see cref="IDistributedCache"/> registered by the caller. ICertificateGenerator is
    /// resolved from the provider, so a test that replaces it is the legacy issuer the registry wraps.
    /// </summary>
    public static IServiceCollection AddIssuerRegistry(this IServiceCollection services)
    {
        services.TryAddSingleton(sp => new IssuerStorage(sp.GetRequiredService<CaDataOptions>()));
        services.TryAddSingleton<IIssuerRegistry>(sp => new IssuerRegistry(
            sp.GetRequiredService<IServiceScopeFactory>(),
            sp.GetRequiredService<ICertificateGenerator>(),
            sp.GetRequiredService<IssuerStorage>(),
            sp.GetRequiredService<IDataProtectionProvider>(),
            sp.GetRequiredService<IDistributedCache>(),
            sp.GetRequiredService<ILoggerFactory>(),
            sp.GetService<TimeProvider>()));
        services.TryAddScoped<IssuanceSigner>();
        services.TryAddScoped<IssuerCrlState>();
        services.TryAddScoped<IssuerCeremonyService>();
        services.TryAddScoped<IssuerLifecycleService>();
        services.TryAddScoped<IssuerRevocationService>();
        services.TryAddSingleton<IssuerKeyExporter>();
        services.TryAddSingleton<FluentValidation.IValidator<CreateIntermediateRequest>, Validators.CreateIntermediateRequestValidator>();
        services.TryAddSingleton<FluentValidation.IValidator<RenewIssuerRequest>, Validators.RenewIssuerRequestValidator>();
        return services;
    }
}
