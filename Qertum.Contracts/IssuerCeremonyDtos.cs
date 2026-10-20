namespace Qertum.Services;

/// <summary>Request body for creating an intermediate issuer.</summary>
public sealed class CreateIntermediateRequest
{
    /// <summary>Unique display name of the new issuer.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Subject CN of the intermediate certificate.</summary>
    public string CommonName { get; set; } = string.Empty;

    /// <summary>Subject O.</summary>
    public string? OrganizationName { get; set; }

    /// <summary>Subject OU.</summary>
    public string? OrganizationalUnit { get; set; }

    /// <summary>Subject C (ISO 3166-1 alpha-2).</summary>
    public string? Country { get; set; }

    /// <summary>Subject ST.</summary>
    public string? State { get; set; }

    /// <summary>Subject L.</summary>
    public string? Locality { get; set; }

    /// <summary>Key algorithm (root-eligible only). Defaults to ECDSA-P384 — a CA key, not the RSA-2048 leaf default.</summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; set; }

    /// <summary>Requested validity in days (1–36500); capped at the parent's notAfter.</summary>
    public int ValidityDays { get; set; } = 1825;

    /// <summary>BasicConstraints pathLenConstraint (0–10); null = unlimited. Default 0 (issues leaves only).</summary>
    public int? PathLength { get; set; } = 0;

    /// <summary>NameConstraints permitted DNS subtrees.</summary>
    public List<string> PermittedDnsSuffixes { get; set; } = [];

    /// <summary>NameConstraints excluded DNS subtrees.</summary>
    public List<string> ExcludedDnsSuffixes { get; set; } = [];

    /// <summary>NameConstraints permitted IP subtrees (CIDR).</summary>
    public List<string> PermittedIpRanges { get; set; } = [];

    /// <summary>NameConstraints excluded IP subtrees (CIDR).</summary>
    public List<string> ExcludedIpRanges { get; set; } = [];

    /// <summary>
    /// The parent issuer. Online and Active: signed immediately. Offline, or omitted: the issuer waits
    /// for its certificate and a request file is returned.
    /// </summary>
    public IssuerId? ParentIssuerId { get; set; }
}

/// <summary>What an offline signer needs to issue a pending intermediate's certificate.</summary>
/// <param name="Format">Always <see cref="CurrentFormat"/>.</param>
/// <param name="IssuerId">The pending issuer.</param>
/// <param name="Name">The pending issuer's name.</param>
/// <param name="CsrPem">PKCS#10 request; carries the same constraints as an extensionRequest.</param>
/// <param name="ValidityDays">Requested validity in days.</param>
/// <param name="PathLength">Requested pathLenConstraint; null = unlimited.</param>
/// <param name="PermittedDnsSuffixes">Requested permitted DNS subtrees.</param>
/// <param name="ExcludedDnsSuffixes">Requested excluded DNS subtrees.</param>
/// <param name="PermittedIpRanges">Requested permitted IP subtrees.</param>
/// <param name="ExcludedIpRanges">Requested excluded IP subtrees.</param>
public sealed record IntermediateRequestFile(
    string Format, IssuerId IssuerId, string Name, string CsrPem, int ValidityDays, int? PathLength,
    IReadOnlyList<string> PermittedDnsSuffixes, IReadOnlyList<string> ExcludedDnsSuffixes,
    IReadOnlyList<string> PermittedIpRanges, IReadOnlyList<string> ExcludedIpRanges)
{
    /// <summary>Format marker of this file.</summary>
    public const string CurrentFormat = "qertum-intermediate-request/1";
}

/// <summary>A created intermediate and, while it waits for its certificate, its request file.</summary>
/// <param name="Issuer">The new issuer.</param>
/// <param name="RequestFile">Null when an online parent signed it immediately.</param>
public sealed record CreateIntermediateResponse(IssuerResponse Issuer, IntermediateRequestFile? RequestFile);

/// <summary>A signed certificate for a pending intermediate, with the chain above it.</summary>
/// <param name="CertificatePem">The intermediate's certificate.</param>
/// <param name="ChainPem">The root and any CA between, in any order; the certificate itself may be repeated.</param>
public sealed record InstallIssuerCertificateRequest(string CertificatePem, string ChainPem);
