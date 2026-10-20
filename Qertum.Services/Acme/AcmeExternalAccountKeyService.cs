using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Acme;

/// <summary>Issues and manages the pre-shared credentials that authorise ACME account creation.</summary>
public interface IAcmeExternalAccountKeyService
{
    Task<IReadOnlyList<AcmeExternalAccountKeyResponse>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a credential. The MAC key is returned once and never again — it is stored encrypted and
    /// there is no endpoint that reads it back.
    /// </summary>
    Task<AcmeExternalAccountKeyCreatedResponse> CreateAsync(string? description, string performedBy, CancellationToken cancellationToken = default);

    Task<AcmeExternalAccountKeyResponse?> SetEnabledAsync(Guid id, bool isEnabled, string performedBy, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(Guid id, string performedBy, CancellationToken cancellationToken = default);
}

public sealed class AcmeExternalAccountKeyService(
    CertificateRequestDbContext dbContext,
    IAuditLogService auditLog) : IAcmeExternalAccountKeyService
{
    public async Task<IReadOnlyList<AcmeExternalAccountKeyResponse>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await dbContext.AcmeExternalAccountKeys
            .AsNoTracking()
            .OrderByDescending(k => k.CreatedAtUtc)
            // Projected without MacKey: listing credentials must not decrypt, let alone return, the
            // secret half of them.
            .Select(k => new AcmeExternalAccountKeyResponse(
                k.Id, k.Kid, k.Description, k.IsEnabled, k.BoundAccountId, k.CreatedAtUtc, k.BoundAtUtc))
            .ToListAsync(cancellationToken);

    public async Task<AcmeExternalAccountKeyCreatedResponse> CreateAsync(
        string? description, string performedBy, CancellationToken cancellationToken = default)
    {
        // 32 bytes of CSPRNG for the MAC key, and a separate random kid so the identifier reveals
        // nothing about the secret.
        var macKey = JwkConverter.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var kid = JwkConverter.Base64UrlEncode(RandomNumberGenerator.GetBytes(16));

        var credential = new AcmeExternalAccountKey
        {
            Kid = kid,
            MacKey = macKey,
            Description = description?.Trim() ?? string.Empty
        };

        dbContext.AcmeExternalAccountKeys.Add(credential);
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("AcmeExternalAccountKeyCreated", performedBy, credential.Id, credential.Kid,
            detail: credential.Description, cancellationToken: cancellationToken);

        return new AcmeExternalAccountKeyCreatedResponse(ToResponse(credential), macKey);
    }

    public async Task<AcmeExternalAccountKeyResponse?> SetEnabledAsync(
        Guid id, bool isEnabled, string performedBy, CancellationToken cancellationToken = default)
    {
        var credential = await dbContext.AcmeExternalAccountKeys.FirstOrDefaultAsync(k => k.Id == id, cancellationToken);
        if (credential is null) return null;

        credential.IsEnabled = isEnabled;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(isEnabled ? "AcmeExternalAccountKeyEnabled" : "AcmeExternalAccountKeyDisabled",
            performedBy, credential.Id, credential.Kid, cancellationToken: cancellationToken);

        return ToResponse(credential);
    }

    public async Task<bool> DeleteAsync(Guid id, string performedBy, CancellationToken cancellationToken = default)
    {
        var credential = await dbContext.AcmeExternalAccountKeys.FirstOrDefaultAsync(k => k.Id == id, cancellationToken);
        if (credential is null) return false;

        dbContext.AcmeExternalAccountKeys.Remove(credential);
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("AcmeExternalAccountKeyDeleted", performedBy, credential.Id, credential.Kid,
            cancellationToken: cancellationToken);

        return true;
    }

    private static AcmeExternalAccountKeyResponse ToResponse(AcmeExternalAccountKey k) =>
        new(k.Id, k.Kid, k.Description, k.IsEnabled, k.BoundAccountId, k.CreatedAtUtc, k.BoundAtUtc);
}
