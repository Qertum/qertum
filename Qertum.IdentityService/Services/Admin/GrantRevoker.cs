using OpenIddict.Abstractions;

namespace Qertum.IdentityService.Services.Admin;

/// <summary>Revokes every stored OpenIddict authorization and token for a user.</summary>
public interface IGrantRevoker
{
    Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken);
}

public sealed class OpenIddictGrantRevoker(IServiceScopeFactory scopeFactory) : IGrantRevoker
{
    public async Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken)
    {
        // The managers are scoped (they sit on the EF context); the admin service is a singleton.
        await using var scope = scopeFactory.CreateAsyncScope();
        var subject = userId.ToString();
        await scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>().RevokeBySubjectAsync(subject, cancellationToken);
        await scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().RevokeBySubjectAsync(subject, cancellationToken);
    }
}
