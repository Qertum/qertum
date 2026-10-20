using Microsoft.EntityFrameworkCore;
using Qertum.Services.Crypto;
using System.Security.Cryptography;

namespace Qertum.Services;

/// <summary>Builds a read-only, certificate-level inventory from issued request rows.</summary>
public sealed class CertificateInventoryService(
    CertificateRequestDbContext db,
    ICertificateGenerator? generator = null,
    Issuers.IIssuerRegistry? issuers = null)
{
    /// <summary>The CA that signs the leaf (Issuing) and the self-verified root of its path.</summary>
    private sealed record RootEvidence(Org.BouncyCastle.X509.X509Certificate Certificate, string? KeyAlgorithm,
        Org.BouncyCastle.X509.X509Certificate Issuing);

    private sealed class Source
    {
        public CertificateRequestId RequestId { get; init; }
        public CertificateRequestId? RenewedFromId { get; init; }
        public DateTime CreatedAtUtc { get; init; }
        public string Leg { get; init; } = string.Empty;
        public int LegOrder { get; init; }
        public string Pem { get; init; } = string.Empty;
        public string? Type { get; init; }
        public CertificateRequestStatus Status { get; init; }
        public string? OwnerSubject { get; init; }
        public string OwnerDisplay { get; init; } = string.Empty;
        public IssuerId? IssuerId { get; init; }
        public CertificateMetadata Metadata { get; init; } = new();
    }

    /// <summary>Returns one page, counting each paired certificate separately.</summary>
    public async Task<PagedResult<CertificateInventoryItem>> GetAsync(
        int page = 1, int pageSize = 100, CancellationToken cancellationToken = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 500);
        var assets = AssetsOf(InventoryPopulation());
        var total = await assets.CountAsync(cancellationToken);
        var sources = await assets.OrderByDescending(r => r.CreatedAtUtc).ThenBy(r => r.RequestId)
            .ThenBy(r => r.LegOrder).Skip((int)Math.Min((long)(page - 1) * pageSize, int.MaxValue))
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        var items = await AnalyzeAsync(sources, cancellationToken);
        return new PagedResult<CertificateInventoryItem>
        {
            Items = items, TotalCount = total, Page = page, PageSize = pageSize
        };
    }

    /// <summary>One <see cref="Source"/> per certificate: the primary leg, plus the PQC leg of a paired request.</summary>
    private static IQueryable<Source> AssetsOf(IQueryable<CertificateRequest> issued)
    {
        var primary = issued.Select(r => new Source
        {
            RequestId = r.Id, RenewedFromId = r.RenewedFromId,
            CreatedAtUtc = r.CreatedAtUtc, Leg = "primary", LegOrder = 0,
            Pem = r.CertificatePem ?? string.Empty,
            Type = r.Type, Status = r.Status, OwnerSubject = r.RequestedBySubject, OwnerDisplay = r.RequestedBy,
            IssuerId = r.IssuerId, Metadata = r.Metadata
        });
        var paired = issued.Where(r => r.PqcCertificatePem != null)
            .Select(r => new Source
            {
                RequestId = r.Id, RenewedFromId = r.RenewedFromId,
                CreatedAtUtc = r.CreatedAtUtc, Leg = "pqc", LegOrder = 1,
                Pem = r.PqcCertificatePem!,
                Type = r.Type, Status = r.Status, OwnerSubject = r.RequestedBySubject, OwnerDisplay = r.RequestedBy,
                IssuerId = r.IssuerId, Metadata = r.Metadata
            });
        return primary.Concat(paired);
    }

    private IQueryable<CertificateRequest> InventoryPopulation() =>
        db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Issued ||
                        r.Status == CertificateRequestStatus.PendingRevocation ||
                        r.Status == CertificateRequestStatus.Revoked);

    private async Task<CertificateInventoryItem[]> AnalyzeAsync(IReadOnlyList<Source> sources, CancellationToken cancellationToken)
    {
        if (issuers is null)
        {
            var root = TryGetVerifiedCurrentRoot();
            return [.. sources.Select(source => Analyze(source, root, source.IssuerId, issuerName: null))];
        }

        // Each row is judged against the CA that signed it (null IssuerId = the legacy issuer).
        var evidence = new Dictionary<IssuerId, (RootEvidence? Path, IssuerId? Id, string? Name)>();
        var list = new List<CertificateInventoryItem>(sources.Count);
        foreach (var source in sources)
        {
            var key = source.IssuerId ?? new IssuerId(Guid.Empty);
            if (!evidence.TryGetValue(key, out var found))
            {
                found = await TryGetIssuerPathAsync(source.IssuerId, cancellationToken);
                evidence[key] = found;
            }
            list.Add(Analyze(source, found.Path, found.Id ?? source.IssuerId, found.Name));
        }
        return [.. list];
    }

    /// <summary>
    /// The inventory's per-certificate facts for exactly <paramref name="requestIds"/>, for callers that
    /// already chose which requests matter (the PQC migration report parses only the page it returns).
    /// Requests that are not issued, pending revocation or revoked have no certificate and are absent.
    /// </summary>
    public async Task<IReadOnlyList<CertificateInventoryItem>> GetForRequestsAsync(
        IReadOnlyCollection<CertificateRequestId> requestIds, CancellationToken cancellationToken = default)
    {
        var sources = new List<Source>();
        foreach (var chunk in requestIds.Distinct().Chunk(500))
        {
            var wanted = chunk.ToList();
            sources.AddRange(await AssetsOf(InventoryPopulation().Where(r => wanted.Contains(r.Id)))
                .ToListAsync(cancellationToken));
        }
        if (sources.Count == 0) return [];

        var ordered = sources.OrderBy(s => s.CreatedAtUtc).ThenBy(s => (Guid)s.RequestId).ThenBy(s => s.LegOrder).ToList();
        return await AnalyzeAsync(ordered, cancellationToken);
    }

    /// <summary>The signing issuer's verified path, and its id and name (synthetic legacy handles have neither).</summary>
    private async Task<(RootEvidence? Path, IssuerId? Id, string? Name)> TryGetIssuerPathAsync(IssuerId? issuerId, CancellationToken ct)
    {
        IssuerId? id = null;
        string? name = null;
        try
        {
            var handle = await issuers!.ForRequestAsync(new CertificateRequest { IssuerId = issuerId }, ct);
            if (handle is null) return (null, null, null);
            if (handle.Issuer.Id.Value != Guid.Empty)
            {
                id = handle.Issuer.Id;
                name = handle.Issuer.Name;
            }
            var chain = await issuers.ChainForAsync(handle.Issuer.Id, ct);
            if (chain.Count == 0) return (null, id, name);
            var issuing = QertumKeyCodec.ReadCertificatePem(chain[0]);
            var evidence = RootEvidenceFrom(chain[^1]);
            return (issuing is null || evidence is null ? null : evidence with { Issuing = issuing }, id, name);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not OperationCanceledException)
        {
            return (null, id, name);
        }
    }

    private static RootEvidence? RootEvidenceFrom(string pem)
    {
        try
        {
            var root = QertumKeyCodec.ReadCertificatePem(pem);
            if (root is null || !root.SubjectDN.Equivalent(root.IssuerDN)) return null;
            root.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root)));
            string? algorithm;
            try { algorithm = CertificateGenerator.DetectAlgorithmFromCertificatePem(pem).ToCanonicalString(); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException) { algorithm = null; }
            return new RootEvidence(root, algorithm, root);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return null;
        }
    }

    private RootEvidence? TryGetVerifiedCurrentRoot()
    {
        if (generator?.IsInitialized != true) return null;
        try { return RootEvidenceFrom(generator.GetCaCertificatePem()); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
    }

    private static CertificateInventoryItem Analyze(Source source, RootEvidence? root, IssuerId? issuerId, string? issuerName)
    {
        var facts = new CertificateInventoryItem
        {
            RequestId = source.RequestId, RenewedFromId = source.RenewedFromId,
            Leg = source.Leg, Type = source.Type,
            Status = source.Status, OwnerSubject = source.OwnerSubject, OwnerDisplay = source.OwnerDisplay,
            Metadata = source.Metadata
        };
        try
        {
            var certificate = QertumKeyCodec.ReadCertificatePem(source.Pem)
                ?? throw new ArgumentException("The stored certificate PEM is empty.");
            var subjectAlgorithm = "Unknown";
            string? analysisError = null;
            try { subjectAlgorithm = CertificateGenerator.DetectAlgorithmFromCertificatePem(source.Pem).ToCanonicalString(); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
            {
                analysisError = "Subject key algorithm is unsupported.";
            }

            string? rootAlgorithm = null;
            string? rootSubject = null;
            string? rootFingerprint = null;
            var chainStatus = "Unknown";
            if (root is not null)
            {
                try
                {
                    if (certificate.IssuerDN.Equivalent(root.Issuing.SubjectDN))
                    {
                        certificate.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root.Issuing)));
                        chainStatus = "SignatureVerifiedWithCurrentRoot";
                        rootAlgorithm = root.KeyAlgorithm;
                        rootSubject = root.Certificate.SubjectDN.ToString();
                        rootFingerprint = Convert.ToHexString(SHA256.HashData(root.Certificate.GetEncoded()));
                    }
                }
                catch (Exception ex) when (ex is not OutOfMemoryException) { }
            }

            return new CertificateInventoryItem
            {
                RequestId = facts.RequestId, RenewedFromId = facts.RenewedFromId,
                IssuerId = issuerId, IssuerName = issuerName,
                Leg = facts.Leg, Type = facts.Type, Status = facts.Status,
                OwnerSubject = facts.OwnerSubject, OwnerDisplay = facts.OwnerDisplay, Metadata = facts.Metadata,
                SerialNumber = certificate.SerialNumber.ToString(16).ToUpperInvariant(),
                SubjectDn = certificate.SubjectDN.ToString(), IssuerDn = certificate.IssuerDN.ToString(),
                SubjectKeyAlgorithm = subjectAlgorithm,
                IssuerSignatureOid = certificate.SigAlgOid,
                IssuerSignatureAlgorithm = SignatureLabel(certificate.SigAlgOid),
                CurrentRootKeyAlgorithm = rootAlgorithm, CurrentRootSubjectDn = rootSubject,
                CurrentRootSha256Fingerprint = rootFingerprint, ChainStatus = chainStatus,
                AnalysisStatus = "Parsed", AnalysisError = analysisError,
                ValidFromUtc = certificate.NotBefore.ToUniversalTime(),
                ValidToUtc = certificate.NotAfter.ToUniversalTime()
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new CertificateInventoryItem
            {
                RequestId = facts.RequestId, RenewedFromId = facts.RenewedFromId,
                IssuerId = issuerId, IssuerName = issuerName,
                Leg = facts.Leg, Type = facts.Type, Status = facts.Status,
                OwnerSubject = facts.OwnerSubject, OwnerDisplay = facts.OwnerDisplay, Metadata = facts.Metadata,
                AnalysisError = "Stored certificate could not be parsed."
            };
        }
    }

    private static string SignatureLabel(string? oid)
    {
        if (oid is not null && CertificateSignatureAlgorithms.PostQuantumSignatureOids.TryGetValue(oid, out var name))
            return name;
        return oid switch
        {
            "1.2.840.113549.1.1.11" => "RSA-SHA256",
            "1.2.840.113549.1.1.12" => "RSA-SHA384",
            "1.2.840.113549.1.1.13" => "RSA-SHA512",
            "1.2.840.10045.4.3.2" => "ECDSA-SHA256",
            "1.2.840.10045.4.3.3" => "ECDSA-SHA384",
            "1.2.840.10045.4.3.4" => "ECDSA-SHA512",
            null => "Unknown",
            _ => oid
        };
    }
}
