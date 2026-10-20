using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Qertum.Services.Auth;

/// <summary>
/// Wires standard OpenID Connect bearer-token authentication and the permission-based
/// authorization policies. Deliberately free of any provider-specific dependency so that
/// any OIDC-compliant issuer can be configured.
/// </summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Binds and validates the "Identity" configuration section, then registers JWT bearer
    /// authentication against the configured issuer.
    /// </summary>
    /// <returns>The validated options, so callers can log or reuse them.</returns>
    /// <exception cref="InvalidOperationException">The Identity section is missing or invalid.</exception>
    public static IdentityAuthenticationOptions AddQertumJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isDevelopment)
    {
        var options = new IdentityAuthenticationOptions();
        configuration.GetSection(IdentityAuthenticationOptions.SectionName).Bind(options);
        options.Validate(isDevelopment);

        services.AddSingleton(options);
        services.AddSingleton(sp => new StepUpEvaluator(options.StepUp, sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<IIdentityClaimsMapper, IdentityClaimsMapper>();
        services.AddSingleton<ICertificateAccessEvaluator, CertificateAccessEvaluator>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwt =>
            {
                jwt.Authority = options.Authority;
                jwt.Audience = options.Audience;
                jwt.RequireHttpsMetadata = options.RequireHttpsMetadata;

                jwt.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        // The one failure an operator cannot diagnose from the token alone: say which two strings differ.
                        if (context.Exception is SecurityTokenInvalidIssuerException issuer)
                            context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Qertum.Auth").LogWarning(
                                "Token rejected: its issuer '{TokenIssuer}' does not equal Identity:Authority '{Authority}'. They must match exactly, including any trailing path and the host name the identity provider advertises.",
                                issuer.InvalidIssuer, options.Authority);
                        return Task.CompletedTask;
                    }
                };

                // Inbound claim types are used verbatim; the claims mapper depends on the
                // provider's original names rather than the legacy SOAP-style mappings.
                jwt.MapInboundClaims = false;

                jwt.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = options.Authority,
                    ValidateAudience = true,
                    ValidAudience = options.Audience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    NameClaimType = options.NameClaimType,
                    RoleClaimType = options.RoleClaimType,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };
            });

        return options;
    }

    /// <summary>
    /// Registers the "admin-role" policy and one policy per entry in
    /// <see cref="AppPermissions.All"/>. The admin role bypasses permission lookups.
    /// </summary>
    public static IServiceCollection AddQertumAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationHandler, AdminRoleAuthorizationHandler>();

        services.AddAuthorization(authorization =>
        {
            // Decided entirely from context.User via AdminRoleAuthorizationHandler — no
            // dependency on context.Resource, so it works for imperative
            // IAuthorizationService calls, SignalR hubs, Blazor [Authorize]/AuthorizeView,
            // and unit tests, not just HTTP endpoint routing.
            authorization.AddPolicy("admin-role", policy =>
                policy.AddRequirements(new AdminRoleRequirement()));

            foreach (var permission in AppPermissions.All)
            {
                authorization.AddPolicy(permission, policy =>
                    policy.RequireAssertion(async context =>
                    {
                        if (context.Resource is not HttpContext httpContext)
                        {
                            return false;
                        }

                        var mapper = httpContext.RequestServices
                            .GetRequiredService<IIdentityClaimsMapper>();

                        if (mapper.IsAdmin(context.User))
                        {
                            return true;
                        }

                        var rolePermissionService = httpContext.RequestServices
                            .GetRequiredService<IRolePermissionService>();

                        var effectivePermissions = await rolePermissionService
                            .GetEffectivePermissionsAsync(mapper.GetRoles(context.User));

                        return effectivePermissions.Contains(permission);
                    }));
            }
        });

        return services;
    }
}
