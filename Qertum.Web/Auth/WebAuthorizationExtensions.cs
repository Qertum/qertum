using Qertum.Services;

namespace Qertum.Web.Auth;

/// <summary>Registers the Web's authorization policies.</summary>
public static class WebAuthorizationExtensions
{
    /// <summary>
    /// One policy per permission, named after the permission itself, satisfied by the matching
    /// <see cref="QertumWebClaims.Permission"/> claim. Pages gate on these rather than on the admin
    /// role, so a deployment that grants <c>settings.edit</c> to its own role gets the pages too.
    /// </summary>
    public static IServiceCollection AddQertumWebAuthorization(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = options.DefaultPolicy;

            foreach (var permission in AppPermissions.All)
            {
                options.AddPolicy(permission, policy =>
                    policy.RequireAssertion(context =>
                        context.User.HasClaim(QertumWebClaims.Permission, permission)));
            }
        });

        return services;
    }
}
