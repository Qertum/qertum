using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Est;

/// <summary>Why a Basic-auth check passed or failed. Internal detail: the endpoint answers every failure identically.</summary>
public enum EstCredentialOutcome
{
    Success,
    UnknownUsername,
    Disabled,
    WrongPassword
}

/// <summary>The outcome, and the matched credential when a username matched one.</summary>
public readonly record struct EstCredentialCheck(EstCredentialOutcome Outcome, Guid? CredentialId);

public interface IEstEnrollmentCredentialService
{
    Task<IReadOnlyList<EstEnrollmentCredentialResponse>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>Issues a credential. The password is returned once and never again — only its hash is stored.</summary>
    Task<EstEnrollmentCredentialCreatedResponse> CreateAsync(string username, string password, string performedBy, string? description = null, CancellationToken cancellationToken = default);

    Task<EstEnrollmentCredentialResponse?> SetEnabledAsync(Guid id, bool isEnabled, string performedBy, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(Guid id, string performedBy, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks a username/password pair for <c>/simpleenroll</c>'s HTTP Basic auth and says why it
    /// failed. The reason is for the diagnostic record only: <c>/simpleenroll</c> answers every failure
    /// with the same 401, so unknown username and wrong password stay indistinguishable to the caller,
    /// the same non-oracle property as EAB's <c>kid</c> lookup.
    /// </summary>
    Task<EstCredentialCheck> CheckAsync(string username, string password, CancellationToken cancellationToken = default);
}

public sealed class EstEnrollmentCredentialService(
    CertificateRequestDbContext dbContext,
    IAuditLogService auditLog) : IEstEnrollmentCredentialService
{
    private readonly PasswordHasher<EstEnrollmentCredential> _hasher = new();

    public async Task<IReadOnlyList<EstEnrollmentCredentialResponse>> GetAllAsync(CancellationToken cancellationToken = default) =>
        await dbContext.EstEnrollmentCredentials
            .AsNoTracking()
            .OrderByDescending(c => c.CreatedAtUtc)
            .Select(c => new EstEnrollmentCredentialResponse(c.Id, c.Username, c.Description, c.IsEnabled, c.CreatedAtUtc))
            .ToListAsync(cancellationToken);

    public async Task<EstEnrollmentCredentialCreatedResponse> CreateAsync(
        string username, string password, string performedBy, string? description = null, CancellationToken cancellationToken = default)
    {
        // Checked ahead of the insert so the common case returns a clean error; the unique index
        // (IX_EstEnrollmentCredentials_Username) is still the source of truth for a concurrent
        // create that lands in between, caught below.
        var duplicate = await dbContext.EstEnrollmentCredentials
            .AnyAsync(c => c.Username == username, cancellationToken);
        if (duplicate) throw new DuplicateEstUsernameException(username);

        var credential = new EstEnrollmentCredential { Username = username, Description = description ?? string.Empty };
        credential.PasswordHash = _hasher.HashPassword(credential, password);

        dbContext.EstEnrollmentCredentials.Add(credential);

        try
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (IsUsernameConflict(ex))
        {
            dbContext.Entry(credential).State = EntityState.Detached;
            throw new DuplicateEstUsernameException(username);
        }

        await auditLog.LogAsync("EstEnrollmentCredentialCreated", performedBy, credential.Id, credential.Username,
            cancellationToken: cancellationToken);

        return new EstEnrollmentCredentialCreatedResponse(ToResponse(credential), password);
    }

    private static bool IsUsernameConflict(DbUpdateException ex)
    {
        var message = ex.InnerException?.Message;
        return message is not null && message.Contains("EstEnrollmentCredentials.Username", StringComparison.Ordinal);
    }

    public async Task<EstEnrollmentCredentialResponse?> SetEnabledAsync(
        Guid id, bool isEnabled, string performedBy, CancellationToken cancellationToken = default)
    {
        var credential = await dbContext.EstEnrollmentCredentials.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential is null) return null;

        credential.IsEnabled = isEnabled;
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync(isEnabled ? "EstEnrollmentCredentialEnabled" : "EstEnrollmentCredentialDisabled",
            performedBy, credential.Id, credential.Username, cancellationToken: cancellationToken);

        return ToResponse(credential);
    }

    public async Task<bool> DeleteAsync(Guid id, string performedBy, CancellationToken cancellationToken = default)
    {
        var credential = await dbContext.EstEnrollmentCredentials.FirstOrDefaultAsync(c => c.Id == id, cancellationToken);
        if (credential is null) return false;

        dbContext.EstEnrollmentCredentials.Remove(credential);
        await dbContext.SaveChangesAsync(cancellationToken);

        await auditLog.LogAsync("EstEnrollmentCredentialDeleted", performedBy, credential.Id, credential.Username,
            cancellationToken: cancellationToken);

        return true;
    }

    public async Task<EstCredentialCheck> CheckAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        var credential = await dbContext.EstEnrollmentCredentials
            .FirstOrDefaultAsync(c => c.Username == username, cancellationToken);
        if (credential is null) return new(EstCredentialOutcome.UnknownUsername, null);
        if (!credential.IsEnabled) return new(EstCredentialOutcome.Disabled, credential.Id);

        var result = _hasher.VerifyHashedPassword(credential, credential.PasswordHash, password);
        return result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded
            ? new(EstCredentialOutcome.Success, credential.Id)
            : new(EstCredentialOutcome.WrongPassword, credential.Id);
    }

    private static EstEnrollmentCredentialResponse ToResponse(EstEnrollmentCredential c) =>
        new(c.Id, c.Username, c.Description, c.IsEnabled, c.CreatedAtUtc);
}
