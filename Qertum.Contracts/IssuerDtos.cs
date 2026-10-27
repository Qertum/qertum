namespace Qertum.Services;

/// <summary>An issuer as the API shows it. Never carries key material.</summary>
/// <param name="Id">Issuer identifier.</param>
/// <param name="Name">Unique display name.</param>
/// <param name="Kind">Root or intermediate.</param>
/// <param name="ParentIssuerId">The issuer that signed this one; null for roots.</param>
/// <param name="KeyCustody">Whether the key is on this server.</param>
/// <param name="Status">Lifecycle state.</param>
/// <param name="IsDefault">Whether this issuer signs when a template names none.</param>
/// <param name="SubjectDn">Subject DN.</param>
/// <param name="SerialNumber">Uppercase hex serial of the issuer's certificate.</param>
/// <param name="KeyAlgorithm">Canonical key algorithm name, or null when unknown.</param>
/// <param name="ValidFrom">Certificate notBefore (UTC).</param>
/// <param name="ValidTo">Certificate notAfter (UTC).</param>
/// <param name="PathLengthConstraint">BasicConstraints pathLenConstraint; null = unlimited.</param>
/// <param name="PermittedDnsSuffixes">NameConstraints permitted DNS subtrees.</param>
/// <param name="ExcludedDnsSuffixes">NameConstraints excluded DNS subtrees.</param>
/// <param name="PermittedIpRanges">NameConstraints permitted IP subtrees (CIDR).</param>
/// <param name="ExcludedIpRanges">NameConstraints excluded IP subtrees (CIDR).</param>
/// <param name="UploadedCrlNumber">Offline issuers: number of the uploaded CRL.</param>
/// <param name="UploadedCrlNextUpdateUtc">Offline issuers: nextUpdate of the uploaded CRL.</param>
/// <param name="CreatedAtUtc">Row creation (UTC).</param>
/// <param name="ActivatedAtUtc">When the issuer became Active (UTC).</param>
/// <param name="RetiredAtUtc">When the issuer was retired (UTC).</param>
/// <param name="ArchivedAtUtc">When the issuer was archived (UTC).</param>
/// <param name="DestroyedAtUtc">When the issuer was destroyed by a force replace (UTC).</param>
/// <param name="RevokedAtUtc">When the issuer's certificate was revoked, or a revoked ancestor took it out of service (UTC).</param>
public sealed record IssuerResponse(
    IssuerId Id, string Name, IssuerKind Kind, IssuerId? ParentIssuerId, IssuerKeyCustody KeyCustody,
    IssuerStatus Status, bool IsDefault, string? SubjectDn, string? SerialNumber, string? KeyAlgorithm,
    DateTime? ValidFrom, DateTime? ValidTo, int? PathLengthConstraint,
    IReadOnlyList<string> PermittedDnsSuffixes, IReadOnlyList<string> ExcludedDnsSuffixes,
    IReadOnlyList<string> PermittedIpRanges, IReadOnlyList<string> ExcludedIpRanges,
    long? UploadedCrlNumber, DateTime? UploadedCrlNextUpdateUtc,
    DateTime CreatedAtUtc, DateTime? ActivatedAtUtc, DateTime? RetiredAtUtc, DateTime? ArchivedAtUtc, DateTime? DestroyedAtUtc,
    DateTime? RevokedAtUtc = null);
