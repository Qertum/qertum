namespace Qertum.Services;

/// <summary>Reports whether a root CA certificate is configured on this server.</summary>
public sealed class CaStatusResponse
{
    /// <summary>True when a CA certificate and key are present on disk.</summary>
    public bool IsInitialized { get; init; }

    /// <summary>X.500 subject distinguished name of the CA certificate, or <see langword="null"/> when not initialized.</summary>
    public string? SubjectDn { get; init; }

    /// <summary>UTC start of the CA certificate's validity window.</summary>
    public DateTime? ValidFrom { get; init; }

    /// <summary>UTC end of the CA certificate's validity window.</summary>
    public DateTime? ValidTo { get; init; }

    /// <summary>Public-key algorithm as a canonical name (e.g. "RSA", "ECDSA-P256", "ML-DSA-65"), or <see langword="null"/> for a key this CA does not issue for.</summary>
    public string? Algorithm { get; init; }

    /// <summary>
    /// True when the CA certificate's ECDSA key carries explicit curve parameters instead of a named
    /// curve. Roots generated before 2026-09-23 were written that way; OpenSSL 3 refuses them in a
    /// chain, and only a new root fixes it. False for every other key.
    /// </summary>
    public bool ExplicitCurveParameters { get; init; }

    /// <summary>What the Web UI and the CLI say when <see cref="ExplicitCurveParameters"/> is true.</summary>
    public const string ExplicitCurveParametersWarning =
        "This root's ECDSA key spells out its curve instead of naming it. OpenSSL 3 rejects every chain " +
        "under it (\"Certificate public key has explicit ECC parameters\"). " +
        "The root cannot be changed, and Qertum cannot replace a root in place yet: the only fix is a new CA " +
        "with a new root, then reissuing every certificate under it.";

    /// <summary>Common Name (CN) extracted from the CA certificate's subject DN.</summary>
    public string? CaCommonName { get; init; }

    /// <summary>Organization (O) extracted from the CA certificate's subject DN.</summary>
    public string? OrganizationName { get; init; }

    /// <summary>Organizational Unit (OU) extracted from the CA certificate's subject DN.</summary>
    public string? OrganizationalUnit { get; init; }

    /// <summary>Two-letter country code (C) extracted from the CA certificate's subject DN.</summary>
    public string? Country { get; init; }

    /// <summary>State or province (ST) extracted from the CA certificate's subject DN.</summary>
    public string? State { get; init; }

    /// <summary>Locality or city (L) extracted from the CA certificate's subject DN.</summary>
    public string? Locality { get; init; }

    /// <summary>
    /// When <see cref="IsInitialized"/> is <see langword="false"/>, the ID of a Root CA
    /// certificate request that is awaiting approval or currently being processed, or
    /// <see langword="null"/> when no such request exists.
    /// </summary>
    public Guid? PendingRootCaRequestId { get; set; }

    /// <summary>The default issuer this status describes; null before any issuer is registered.</summary>
    public IssuerId? DefaultIssuerId { get; set; }

    /// <summary>Display name of <see cref="DefaultIssuerId"/>.</summary>
    public string? DefaultIssuerName { get; set; }

    /// <summary>An intermediate waiting for its signed certificate (offline-root onboarding in progress), or null.</summary>
    public IssuerId? PendingIntermediateIssuerId { get; set; }

    /// <summary>
    /// True when <see cref="IsInitialized"/> is false because a revoked CA certificate took the issuers out of
    /// service, not because no CA was ever set up. The UI then explains that, and still lets an administrator
    /// open the other pages (issuers, audit log) instead of forcing onboarding.
    /// </summary>
    public bool IssuerRevoked { get; set; }

    /// <summary>
    /// While <see cref="IssuerRevoked"/>: the kind of the most recently revoked issuer, so the UI can point to where
    /// that kind renews (a root from its certificate page, an intermediate from the Issuers page). Null otherwise.
    /// </summary>
    public IssuerKind? RevokedIssuerKind { get; set; }
}
