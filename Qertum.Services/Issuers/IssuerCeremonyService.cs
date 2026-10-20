using Org.BouncyCastle.X509;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Security;
using Qertum.Services.Crypto;

namespace Qertum.Services.Issuers;

/// <summary>
/// Issuer ceremonies: create an intermediate (signed now by an online parent, or as a request file
/// for an offline one), install its signed certificate, publish an offline root's CRL, abandon a
/// pending ceremony. Every mutation is audited, raises an Issuer-family webhook and invalidates the
/// registry so every host sees it.
/// </summary>
public sealed class IssuerCeremonyService(
    CertificateRequestDbContext db,
    IIssuerRegistry issuers,
    IssuerStorage storage,
    IDataProtectionProvider dataProtection,
    ICertificateRequestService requests,
    IAuditLogService audit,
    IWebhookService webhooks,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly IDataProtector _keyProtector = dataProtection.CreateProtector("Qertum.CaPrivateKey");

    public async Task<IssuerOutcome<CreateIntermediateResponse>> CreateIntermediateAsync(
        CreateIntermediateRequest request, string performedBy, CancellationToken ct)
    {
        var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.EcdsaP384;
        var settings = await requests.GetSettingsAsync(ct);
        // A CA key has no template, so the CA default stage governs and no exception applies.
        var pqcVerdict = PqcStageEvaluator.Evaluate(settings.PqcStage, algorithm, isRenewal: false);
        if (pqcVerdict.Outcome == PqcOutcome.Refused)
            return IssuerOutcome<CreateIntermediateResponse>.Invalid(pqcVerdict.Reason!);

        if (await db.Issuers.AnyAsync(i => i.Name == request.Name, ct))
            return IssuerOutcome<CreateIntermediateResponse>.Conflict($"An issuer named '{request.Name}' already exists.");

        IssuerHandle? parent = null;
        if (request.ParentIssuerId is { } parentId)
        {
            parent = await issuers.GetAsync(parentId, ct);
            if (parent is null)
                return IssuerOutcome<CreateIntermediateResponse>.NotFound($"Parent issuer {parentId} does not exist.");
            var offlineAnchor = parent.Issuer.KeyCustody == IssuerKeyCustody.Offline && parent.Issuer.Status == IssuerStatus.Active;
            if (!parent.CanIssue && !offlineAnchor)
                return IssuerOutcome<CreateIntermediateResponse>.Conflict(
                    $"Parent issuer '{parent.Issuer.Name}' cannot sign (status {parent.Issuer.Status}, {parent.Issuer.KeyCustody}).");
            if (parent.Issuer.PathLengthConstraint is 0)
                return IssuerOutcome<CreateIntermediateResponse>.Conflict(
                    $"Parent issuer '{parent.Issuer.Name}' has path length 0 and cannot sign another CA.");
        }

        var profile = new SubordinateCaProfile(request.PathLength,
            Normalize(request.PermittedDnsSuffixes), Normalize(request.ExcludedDnsSuffixes),
            NormalizeIp(request.PermittedIpRanges), NormalizeIp(request.ExcludedIpRanges));
        var subject = CaCertificateBuilder.SubjectName(request.CommonName, request.OrganizationName,
            request.OrganizationalUnit, request.Country, request.State, request.Locality);
        var keyPair = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());
        var csr = CaCertificateBuilder.BuildRequest(keyPair, subject, profile);
        var now = _clock.GetUtcNow().UtcDateTime;

        var issuer = new Issuer
        {
            Name = request.Name,
            Kind = IssuerKind.Intermediate,
            ParentIssuerId = parent?.Issuer.Id,
            KeyCustody = IssuerKeyCustody.Online,
            Status = IssuerStatus.PendingCertificate,
            CsrPem = QertumKeyCodec.WriteCertificationRequestPem(csr),
            KeyAlgorithm = algorithm,
            SubjectDn = subject.ToString(),
            SpkiSha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                QertumKeyCodec.ToSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded())),
            RequestedConstraintsJson = JsonSerializer.Serialize(new RequestedConstraints(request.ValidityDays, profile)),
            CreatedAtUtc = now
        };

        Directory.CreateDirectory(storage.DirectoryFor(issuer));
        await File.WriteAllTextAsync(storage.KeyPath(issuer), _keyProtector.Protect(QertumKeyCodec.WritePrivateKeyPem(keyPair.Private)), ct);

        try
        {
            if (parent is { CanIssue: true })
            {
                var certificate = parent.Generator!.IssueSubordinateCa(
                    QertumKeyCodec.ToSubjectPublicKeyInfo(keyPair.Public), subject, profile,
                    now.AddDays(request.ValidityDays), IssuerUrls.For(parent.Issuer, settings));
                var pem = QertumKeyCodec.WriteCertificatePem(certificate);
                await File.WriteAllTextAsync(storage.CertificatePath(issuer), pem, ct);
                Activate(issuer, pem, now);
                issuer.IsDefault = !await db.Issuers.AnyAsync(i => i.IsDefault, ct);
            }

            db.Issuers.Add(issuer);
            await db.SaveChangesAsync(ct);
        }
        catch
        {
            storage.DeleteFiles(issuer);
            throw;
        }

        var detail = issuer.Status == IssuerStatus.Active
            ? $"Intermediate signed by '{parent!.Issuer.Name}'. {IssuerCeremonyText.Describe(profile)}"
            : $"Intermediate pending; request file issued. {IssuerCeremonyText.Describe(profile)}";
        await audit.LogAsync("IssuerCreated", performedBy, (Guid)issuer.Id, issuer.Name, detail, ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerCreated, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);

        return IssuerOutcome<CreateIntermediateResponse>.Ok(new CreateIntermediateResponse(
            IssuerMapping.ToResponse(issuer),
            issuer.Status == IssuerStatus.PendingCertificate ? RequestFileFor(issuer) : null));
    }

    public async Task<IssuerOutcome<IntermediateRequestFile>> GetRequestFileAsync(IssuerId id, CancellationToken ct)
    {
        var issuer = await db.Issuers.AsNoTracking().FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<IntermediateRequestFile>.NotFound($"Issuer {id} does not exist.");
        if (issuer.CsrPem is null || issuer.RequestedConstraintsJson is null)
            return IssuerOutcome<IntermediateRequestFile>.Conflict($"Issuer '{issuer.Name}' has no request file.");
        return IssuerOutcome<IntermediateRequestFile>.Ok(RequestFileFor(issuer));
    }

    public async Task<IssuerOutcome<bool>> DeletePendingAsync(IssuerId id, string performedBy, CancellationToken ct)
    {
        var issuer = await db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<bool>.NotFound($"Issuer {id} does not exist.");
        if (issuer.Status != IssuerStatus.PendingCertificate)
            return IssuerOutcome<bool>.Conflict(
                $"Only a pending ceremony can be deleted; '{issuer.Name}' is {issuer.Status}. Retire and archive it instead.");

        db.Issuers.Remove(issuer);
        await db.SaveChangesAsync(ct);
        storage.DeleteFiles(issuer);
        await audit.LogAsync("IssuerDeleted", performedBy, (Guid)issuer.Id, issuer.Name, "Pending ceremony abandoned; key deleted.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerDeleted, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<bool>.Ok(true);
    }

    public async Task<IssuerOutcome<IssuerResponse>> InstallCertificateAsync(
        IssuerId id, InstallIssuerCertificateRequest body, string performedBy, CancellationToken ct)
    {
        var issuer = await db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<IssuerResponse>.NotFound($"Issuer {id} does not exist.");
        if (issuer.Status != IssuerStatus.PendingCertificate)
            return IssuerOutcome<IssuerResponse>.Conflict($"Issuer '{issuer.Name}' is {issuer.Status}; only a pending issuer takes a certificate.");

        X509Certificate certificate;
        IReadOnlyList<X509Certificate> chain;
        try
        {
            certificate = QertumKeyCodec.ReadCertificatePem(body.CertificatePem)
                          ?? throw new ArgumentException("certificatePem holds no certificate.");
            chain = ChainVerifier.ReadAll(body.ChainPem ?? string.Empty);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or Org.BouncyCastle.Security.Certificates.CertificateException)
        {
            return IssuerOutcome<IssuerResponse>.Invalid(ex.Message);
        }

        var facts = IssuerCertificateFacts.Read(certificate);
        if (facts.SpkiSha256 != issuer.SpkiSha256)
            return IssuerOutcome<IssuerResponse>.Invalid("The certificate's public key is not the pending key of this issuer.");
        if (!facts.IsCa || !facts.HasKeyCertSign)
            return IssuerOutcome<IssuerResponse>.Invalid("The certificate is not a CA certificate (BasicConstraints cA and keyCertSign are required).");

        var built = ChainVerifier.Build(certificate, chain);
        if (built.Path is null) return IssuerOutcome<IssuerResponse>.Invalid(built.Error!);
        var path = built.Path;

        var now = _clock.GetUtcNow().UtcDateTime;
        if (certificate.NotAfter.ToUniversalTime() <= now)
            return IssuerOutcome<IssuerResponse>.Invalid("The certificate has already expired.");
        for (var i = 1; i < path.Count; i++)
        {
            var parentFacts = IssuerCertificateFacts.Read(path[i]);
            if (!parentFacts.IsCa || !parentFacts.HasKeyCertSign)
                return IssuerOutcome<IssuerResponse>.Invalid($"'{path[i].SubjectDN}' in the chain is not a CA certificate.");
            if (path[i - 1].NotAfter > path[i].NotAfter || path[i - 1].NotBefore < path[i].NotBefore)
                return IssuerOutcome<IssuerResponse>.Invalid(
                    $"'{path[i - 1].SubjectDN}' would outlive (or predate) the CA that signed it, '{path[i].SubjectDN}'.");
        }

        var weaker = WeakerThanRequested(facts, RequestedProfile(issuer));
        if (weaker is not null) return IssuerOutcome<IssuerResponse>.Invalid(weaker);

        // Register every CA above this one we do not know yet, as offline issuers, linking parents.
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        IssuerId? childParent = null;
        var registered = new List<Issuer>();
        for (var i = path.Count - 1; i >= 1; i--)
        {
            var caFacts = IssuerCertificateFacts.Read(path[i]);
            var known = await db.Issuers.FirstOrDefaultAsync(x => x.SpkiSha256 == caFacts.SpkiSha256, ct);
            if (known is null)
            {
                known = new Issuer
                {
                    Name = await UniqueNameAsync(IssuerBootstrap.NameFrom(caFacts.SubjectDn), ct),
                    Kind = caFacts.IsSelfSigned ? IssuerKind.Root : IssuerKind.Intermediate,
                    ParentIssuerId = childParent,
                    KeyCustody = IssuerKeyCustody.Offline,
                    Status = IssuerStatus.Active,
                    CertificatePem = QertumKeyCodec.WriteCertificatePem(path[i]),
                    CreatedAtUtc = now,
                    ActivatedAtUtc = now
                };
                caFacts.ApplyTo(known);
                db.Issuers.Add(known);
                await db.SaveChangesAsync(ct);
                registered.Add(known);
            }
            childParent = known.Id;
        }

        if (issuer.ParentIssuerId is { } named && named != childParent)
            return IssuerOutcome<IssuerResponse>.Invalid("The certificate was signed by a different CA than the parent named when the intermediate was created.");

        var pem = QertumKeyCodec.WriteCertificatePem(certificate);
        await File.WriteAllTextAsync(storage.CertificatePath(issuer), pem, ct);
        issuer.ParentIssuerId = childParent;
        Activate(issuer, pem, now);
        issuer.IsDefault = !await db.Issuers.AnyAsync(i => i.IsDefault, ct);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        foreach (var added in registered)
        {
            await audit.LogAsync("IssuerRegistered", performedBy, (Guid)added.Id, added.Name,
                "Offline CA registered from an installed chain.", ct);
            await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRegistered, added, performedBy), ct);
        }
        await audit.LogAsync("IssuerCertificateInstalled", performedBy, (Guid)issuer.Id, issuer.Name,
            $"Signed by '{path[1].SubjectDN}', valid to {certificate.NotAfter:yyyy-MM-dd}. {IssuerCeremonyText.Describe(RequestedProfile(issuer))}", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerCertificateInstalled, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));
    }

    public async Task<IssuerOutcome<IssuerResponse>> UploadCrlAsync(IssuerId id, byte[] body, string performedBy, CancellationToken ct)
    {
        var issuer = await db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<IssuerResponse>.NotFound($"Issuer {id} does not exist.");
        if (issuer.KeyCustody != IssuerKeyCustody.Offline || issuer.Status is not (IssuerStatus.Active or IssuerStatus.Retired))
            return IssuerOutcome<IssuerResponse>.Conflict("Only an active or retired offline issuer publishes an uploaded CRL; online issuers sign their own.");

        X509Crl crl;
        try
        {
            var text = System.Text.Encoding.ASCII.GetString(body);
            var der = text.Contains("-----BEGIN X509 CRL-----", StringComparison.Ordinal)
                ? Convert.FromBase64String(string.Concat(text.Split('\n')
                    .Where(l => !l.StartsWith("-----", StringComparison.Ordinal)).Select(l => l.Trim())))
                : body;
            crl = new X509CrlParser().ReadCrl(der) ?? throw new ArgumentException("The body holds no CRL.");
            body = crl.GetEncoded();
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or IOException or Org.BouncyCastle.Security.Certificates.CrlException)
        {
            return IssuerOutcome<IssuerResponse>.Invalid($"The CRL could not be parsed: {ex.Message}");
        }

        var issuerCert = QertumKeyCodec.ReadCertificatePem(issuer.CertificatePem!)!;
        if (!crl.IssuerDN.Equivalent(issuerCert.SubjectDN))
            return IssuerOutcome<IssuerResponse>.Invalid($"The CRL is issued by '{crl.IssuerDN}', not '{issuerCert.SubjectDN}'.");
        bool signatureValid;
        try { signatureValid = crl.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(issuerCert))); }
        catch (Exception) { signatureValid = false; }
        if (!signatureValid)
            return IssuerOutcome<IssuerResponse>.Invalid("The CRL's signature does not verify with this issuer's key.");

        var numberExtension = crl.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber);
        if (numberExtension is null)
            return IssuerOutcome<IssuerResponse>.Invalid("The CRL has no CRL number extension.");
        var number = Org.BouncyCastle.Asn1.DerInteger.GetInstance(
            Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(numberExtension)).LongValueExact;
        if (issuer.UploadedCrlNumber is long last && number <= last)
            return IssuerOutcome<IssuerResponse>.Invalid($"CRL number {number} is not newer than the published {last}.");
        var now = _clock.GetUtcNow().UtcDateTime;
        if (crl.NextUpdate is not { } nextUpdate || nextUpdate.ToUniversalTime() <= now)
            return IssuerOutcome<IssuerResponse>.Invalid("The CRL's nextUpdate is missing or already passed.");

        issuer.UploadedCrlDer = body;
        issuer.UploadedCrlNumber = number;
        issuer.UploadedCrlNextUpdateUtc = nextUpdate.ToUniversalTime();

        // An intermediate this root revoked stops issuing; Qertum does not destroy it on its own.
        var revokedSerials = (crl.GetRevokedCertificates() ?? new HashSet<X509CrlEntry>())
            .Select(e => e.SerialNumber.ToString(16).ToUpperInvariant()).ToHashSet(StringComparer.Ordinal);
        var retired = await db.Issuers
            .Where(i => i.ParentIssuerId == issuer.Id && i.SerialNumber != null && i.Status == IssuerStatus.Active)
            .ToListAsync(ct);
        retired = [.. retired.Where(i => revokedSerials.Contains(i.SerialNumber!))];
        foreach (var child in retired.Where(c => c.IsDefault))
        {
            child.IsDefault = false; // clear first: the filtered unique index is checked per statement
        }
        await db.SaveChangesAsync(ct);
        foreach (var child in retired)
        {
            child.Status = IssuerStatus.Retired;
            child.RetiredAtUtc = now;
        }
        await db.SaveChangesAsync(ct);

        await audit.LogAsync("IssuerCrlUploaded", performedBy, (Guid)issuer.Id, issuer.Name,
            $"crlNumber={number}, nextUpdate={nextUpdate:u}, revoked={revokedSerials.Count}", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerCrlUploaded, issuer, performedBy), ct);
        foreach (var child in retired)
        {
            await audit.LogAsync("IssuerRetired", performedBy, (Guid)child.Id, child.Name,
                $"Revoked on the CRL of '{issuer.Name}' (crlNumber={number}).", ct);
            await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRetired, child, performedBy), ct);
        }
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));
    }

    /// <summary>A refusal naming the first constraint the certificate relaxes relative to the request, or null.</summary>
    internal static string? WeakerThanRequested(IssuerCertificateFacts actual, SubordinateCaProfile requested)
    {
        if (requested.PathLength is int wantedPathLength &&
            (actual.PathLengthConstraint is not int got || got > wantedPathLength))
            return $"The certificate's path length constraint is {(actual.PathLengthConstraint?.ToString() ?? "missing")}; the request asked for at most {wantedPathLength}.";

        if (requested.PermittedDnsSuffixes.Count > 0)
        {
            if (actual.PermittedDnsSuffixes.Count == 0)
                return $"The certificate drops the permitted DNS subtrees ({string.Join(", ", requested.PermittedDnsSuffixes)}).";
            var outside = actual.PermittedDnsSuffixes.FirstOrDefault(a => !requested.PermittedDnsSuffixes.Any(r => NameConstraintMatcher.SuffixWithin(a, r)));
            if (outside is not null) return $"The certificate permits '{outside}', which the request did not.";
        }
        var droppedDns = requested.ExcludedDnsSuffixes.FirstOrDefault(r => !actual.ExcludedDnsSuffixes.Any(a => NameConstraintMatcher.SuffixWithin(r, a)));
        if (droppedDns is not null) return $"The certificate does not exclude '{droppedDns}' as requested.";

        if (requested.PermittedIpRanges.Count > 0)
        {
            if (actual.PermittedIpRanges.Count == 0)
                return $"The certificate drops the permitted IP subtrees ({string.Join(", ", requested.PermittedIpRanges)}).";
            var outside = actual.PermittedIpRanges.FirstOrDefault(a => !requested.PermittedIpRanges.Any(r => NameConstraintMatcher.CidrWithin(a, r)));
            if (outside is not null) return $"The certificate permits '{outside}', which the request did not.";
        }
        var droppedIp = requested.ExcludedIpRanges.FirstOrDefault(r => !actual.ExcludedIpRanges.Any(a => NameConstraintMatcher.CidrWithin(r, a)));
        return droppedIp is null ? null : $"The certificate does not exclude '{droppedIp}' as requested.";
    }

    private Task<string> UniqueNameAsync(string wanted, CancellationToken ct) => IssuerNames.UniqueAsync(db, wanted, ct);

    internal sealed record RequestedConstraints(int ValidityDays, SubordinateCaProfile Profile);

    internal static SubordinateCaProfile RequestedProfile(Issuer issuer) =>
        JsonSerializer.Deserialize<RequestedConstraints>(issuer.RequestedConstraintsJson!)!.Profile;

    internal static IntermediateRequestFile RequestFileFor(Issuer issuer)
    {
        var requested = JsonSerializer.Deserialize<RequestedConstraints>(issuer.RequestedConstraintsJson!)!;
        var p = requested.Profile;
        return new IntermediateRequestFile(IntermediateRequestFile.CurrentFormat, issuer.Id, issuer.Name, issuer.CsrPem!,
            requested.ValidityDays, p.PathLength, p.PermittedDnsSuffixes, p.ExcludedDnsSuffixes, p.PermittedIpRanges, p.ExcludedIpRanges);
    }

    private static void Activate(Issuer issuer, string certificatePem, DateTime now)
    {
        issuer.CertificatePem = certificatePem;
        IssuerCertificateFacts.Read(certificatePem).ApplyTo(issuer);
        issuer.Status = IssuerStatus.Active;
        issuer.ActivatedAtUtc = now;
    }

    private static List<string> Normalize(IEnumerable<string> suffixes) =>
        [.. suffixes.Select(s => Policies.IssuancePolicyEvaluator.NormalizeDns(s)!).Distinct(StringComparer.Ordinal)];

    private static List<string> NormalizeIp(IEnumerable<string> ranges) =>
        [.. ranges.Select(r => System.Net.IPNetwork.Parse(r).ToString()).Distinct(StringComparer.Ordinal)];
}
