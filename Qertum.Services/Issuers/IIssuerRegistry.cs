namespace Qertum.Services.Issuers;

/// <summary>Which issued rows belong to an issuer. The legacy issuer also owns rows with a null IssuerId.</summary>
public readonly record struct IssuerScope(IssuerId IssuerId, bool IncludesUnassigned);

/// <summary>An issuer row and, when it can sign here, the generator that signs as it.</summary>
public sealed record IssuerHandle(Issuer Issuer, ICertificateGenerator? Generator)
{
    /// <summary>Active, online, key loaded: may sign new certificates.</summary>
    public bool CanIssue => Generator is not null && Issuer.Status == IssuerStatus.Active;

    /// <summary>Active or Retired with a key loaded: may sign CRLs and OCSP responses.</summary>
    public bool CanSignRevocation => Generator is not null && Issuer.Status is IssuerStatus.Active or IssuerStatus.Retired;

    /// <summary>The rows this issuer answers revocation for.</summary>
    public IssuerScope Scope => new(Issuer.Id, Issuer.LegacyFiles);

    /// <summary>The id to store on an issued row; null for the synthetic fallback (bootstrap back-fills nulls).</summary>
    public IssuerId? RecordedIssuerId => Issuer.Id.Value == Guid.Empty ? null : Issuer.Id;
}

/// <summary>Every issuer this server knows, with a generator for each one that signs here.</summary>
public interface IIssuerRegistry
{
    /// <summary>Every issuer row, oldest first.</summary>
    Task<IReadOnlyList<Issuer>> GetAllAsync(CancellationToken ct = default);

    /// <summary>The default issuer, or null when no CA exists yet.</summary>
    Task<IssuerHandle?> GetDefaultAsync(CancellationToken ct = default);

    /// <summary>One issuer, or null when unknown.</summary>
    Task<IssuerHandle?> GetAsync(IssuerId id, CancellationToken ct = default);

    /// <summary>The issuer of an issued row: its IssuerId, or the legacy issuer when null.</summary>
    Task<IssuerHandle?> ForRequestAsync(CertificateRequest request, CancellationToken ct = default);

    /// <summary>The template's pinned issuer, else the default. Throws CaNotInitializedException / IssuerNotActiveException.</summary>
    Task<IssuerHandle> ForIssuanceAsync(CertificateTemplate? template, CancellationToken ct = default);

    /// <summary>PEMs from <paramref name="id"/> up to and including its root. Empty when unknown.</summary>
    Task<IReadOnlyList<string>> ChainForAsync(IssuerId id, CancellationToken ct = default);

    /// <summary>
    /// The Active/Retired issuer (with its key here) whose certificate matches the first CertID of
    /// a DER OCSP request, or null. Throws the parse exceptions of a malformed request.
    /// </summary>
    Task<IssuerHandle?> MatchOcspIssuerAsync(byte[] derRequest, CancellationToken ct = default);

    /// <summary>Rows from <paramref name="id"/> up to its root (index 0 = the issuing CA). Empty when unknown.</summary>
    Task<IReadOnlyList<Issuer>> PathForAsync(IssuerId id, CancellationToken ct = default);

    /// <summary>Publishes a new stamp so every host reloads on its next call.</summary>
    Task InvalidateAsync(CancellationToken ct = default);
}
