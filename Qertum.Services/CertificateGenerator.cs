using System.Security.Cryptography;
using System.Text.Json;
using System.Net;
using Qertum.Services.Crypto;
using Qertum.Services.Policies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Qertum.Services;

public sealed class WebServerProperties
{
    public List<string> DnsNames { get; init; } = [];
}

public sealed class CertificateProperties
{
    public List<string> DnsNames { get; init; } = [];
    public List<string> IpAddresses { get; init; } = [];
    public List<string> EmailAddresses { get; init; } = [];
    public List<string> UserPrincipalNames { get; init; } = [];
}

public sealed class CustomExtension
{
    public string Oid { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public bool Critical { get; set; }
}

public sealed class GeneratedCertificate
{
    public string CertificatePem { get; init; } = string.Empty;
    public string PrivateKeyPem { get; init; } = string.Empty;
    public DateTime ValidFrom { get; init; }
    public DateTime ValidTo { get; init; }
    /// <summary>
    /// Uppercase hex serial number of the certificate in <see cref="CertificatePem"/>. Reported so
    /// callers can persist and index it without re-parsing the PEM. For hybrid paired issuance this
    /// is the classical certificate's serial; the PQC certificate carries its own.
    /// </summary>
    public string SerialNumber { get; init; } = string.Empty;
    /// <summary>Uppercase hex serial number of <see cref="PqcCertificatePem"/>. Null unless that is set.</summary>
    public string? PqcSerialNumber { get; init; }
    /// <summary>Second certificate PEM of a paired request (hybrid PQC certificate, or the encryption certificate of a pair). Null for unpaired requests.</summary>
    public string? PqcCertificatePem { get; init; }
    /// <summary>Private key PEM of the second certificate of a paired request. Null for unpaired requests.</summary>
    public string? PqcPrivateKeyPem { get; init; }
    /// <summary>The issuer that signed it; set by <see cref="Issuers.IssuanceSigner"/>, stored by MarkAsIssuedAsync.</summary>
    public IssuerId? IssuerId { get; set; }
}


public sealed class CertificateGenerator(
    IDataProtectionProvider dataProtectionProvider,
    CaDataOptions caDataOptions,
    ILogger<CertificateGenerator> logger,
    // How a loaded key pair becomes a signer. Defaults to signing in-process; the point of the
    // indirection is that nothing below this line touches the private key directly, so a signer
    // whose key lives in a vault can be substituted without revisiting any signing path.
    Func<AsymmetricCipherKeyPair, ICaSigner>? caSignerFactory = null,
    TimeProvider? timeProvider = null) : ICertificateGenerator
{
    // Validity windows, CRL/OCSP times and revocation fallbacks read this clock; optional so the many
    // tests that construct the generator directly keep compiling.
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    private readonly Func<AsymmetricCipherKeyPair, ICaSigner> _caSignerFactory =
        caSignerFactory ?? (pair => new LocalKeyPairCaSigner(pair));

    private ICaSigner? _caSigner;
    private X509Certificate? _caCertificate;
    private readonly Lock _initLock = new();
    private readonly IDataProtector _keyProtector = dataProtectionProvider.CreateProtector("Qertum.CaPrivateKey");
    private readonly ILogger<CertificateGenerator> _logger = logger;
    private readonly string _caDataDirectory = caDataOptions.Directory;

    public bool IsInitialized
    {
        get
        {
            var caCertPath = Path.Combine(_caDataDirectory, "ca.pem");
            var caKeyPath = Path.Combine(_caDataDirectory, "ca.key");
            return File.Exists(caCertPath) && File.Exists(caKeyPath);
        }
    }

    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
        => GenerateCertificate(request, caSettings, template, urls: null);

    /// <inheritdoc />
    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template, Issuers.IssuerUrls? urls)
    {
        EnsureCaInitialized();

        var random = new SecureRandom();
        var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;

        if (!algorithm.IsPaired())
            return BuildSingleCertificate(algorithm, request, caSettings, template, random, urls: urls);

        // A pair is two certificates from one request, built in order; if either fails the exception
        // leaves no partial result for the caller to store.
        var (firstAlgorithm, secondAlgorithm) = PairedAlgorithms.For(algorithm);
        var issuedAt = _clock.GetUtcNow().UtcDateTime;
        var first = BuildSingleCertificate(firstAlgorithm, request, caSettings, template, random, urls: urls, issuedAtUtc: issuedAt);
        var second = BuildSingleCertificate(secondAlgorithm, request, caSettings, template, random, urls: urls, issuedAtUtc: issuedAt);
        return new GeneratedCertificate
        {
            CertificatePem = first.CertificatePem,
            PrivateKeyPem = first.PrivateKeyPem,
            PqcCertificatePem = second.CertificatePem,
            PqcPrivateKeyPem = second.PrivateKeyPem,
            // Each certificate of the pair has its own serial, and each is indexed, looked up by OCSP
            // and listed on the CRL in its own right.
            SerialNumber = first.SerialNumber,
            PqcSerialNumber = second.SerialNumber,
            ValidFrom = first.ValidFrom,
            ValidTo = first.ValidTo
        };
    }

    public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
        => GenerateFromCsr(csrDerBase64Url, request, caSettings, template, urls: null);

    /// <inheritdoc />
    public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template, Issuers.IssuerUrls? urls)
    {
        EnsureCaInitialized();

        var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        if (algorithm.IsPaired())
            throw new NotSupportedException("Paired (hybrid or signing + encryption) algorithms are not supported for CSR-based issuance.");

        var csrBytes = Base64UrlText.Decode(csrDerBase64Url);
        var csr = new Pkcs10CertificationRequest(csrBytes);
        if (!QertumKeyCodec.VerifySelfSignature(csr))
            throw new ArgumentException("CSR signature verification failed.");

        var csrPublicKey = QertumKeyCodec.PublicKeyOf(csr);
        var random = new SecureRandom();
        return BuildSingleCertificate(algorithm, request, caSettings, template, random, externalPublicKey: csrPublicKey, urls: urls);
    }

    private GeneratedCertificate BuildSingleCertificate(CertificateKeyAlgorithm algorithm, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template, SecureRandom random, AsymmetricKeyParameter? externalPublicKey = null, Issuers.IssuerUrls? urls = null, DateTime? issuedAtUtc = null)
    {
        var strategy = AlgorithmStrategyFactory.Create(algorithm);
        AsymmetricCipherKeyPair? leafKeyPair = externalPublicKey is null ? strategy.GenerateLeafKeyPair(random) : null;
        var leafPublicKey = externalPublicKey ?? leafKeyPair!.Public;

        var nameAttrs = new List<string> { $"CN={request.CommonName}" };
        if (caSettings != null)
        {
            if (!string.IsNullOrWhiteSpace(caSettings.OrganizationName)) nameAttrs.Add($"O={caSettings.OrganizationName}");
            if (!string.IsNullOrWhiteSpace(caSettings.OrganizationalUnit)) nameAttrs.Add($"OU={caSettings.OrganizationalUnit}");
            if (!string.IsNullOrWhiteSpace(caSettings.Country)) nameAttrs.Add($"C={caSettings.Country}");
            if (!string.IsNullOrWhiteSpace(caSettings.State)) nameAttrs.Add($"ST={caSettings.State}");
            if (!string.IsNullOrWhiteSpace(caSettings.Locality)) nameAttrs.Add($"L={caSettings.Locality}");
        }

        var subjectName = new X509Name(string.Join(", ", nameAttrs));
        var serialNumber = GenerateSerialNumber(random);

        // One reading of the clock per certificate, or per pair: both bounds, and both certificates of a
        // pair, share the instant instead of straddling a second boundary.
        var issuedAt = issuedAtUtc ?? _clock.GetUtcNow().UtcDateTime;
        var validFrom = issuedAt.AddMinutes(-5);
        var validityDays = Policies.ValidityDefaults.EffectiveValidityDays(request, template, caSettings);
        var validTo = issuedAt.AddDays(validityDays);

        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(serialNumber);
        certGen.SetIssuerDN(_caCertificate!.SubjectDN);
        certGen.SetNotBefore(validFrom);
        certGen.SetNotAfter(validTo);
        certGen.SetSubjectDN(subjectName);
        certGen.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(leafPublicKey));

        var isSubordinateCa = CaCapableTemplate.IsCaCapable(template);
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isSubordinateCa));

        // RFC 5280 §4.2.1.2/4.2.1.1. Without these, chain builders fall back to matching by
        // Distinguished Name, which becomes ambiguous the moment the CA rotates its key: two CA certs
        // share a subject and a validator cannot tell which one signed this certificate.
        // AKI is derived from the CA's public key, so it identifies the correct issuer even though
        // the existing root cert carries no SubjectKeyIdentifier of its own.
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
            QertumKeyCodec.SubjectKeyIdentifierFor(leafPublicKey));
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            QertumKeyCodec.AuthorityKeyIdentifierFor(_caCertificate));

        var ocspUrl = urls is null ? caSettings?.OcspResponderUrl : urls.OcspResponderUrl;
        var caIssuersUrl = urls?.CaIssuersUrl;
        var accessDescriptions = new List<AccessDescription>();
        if (!string.IsNullOrWhiteSpace(ocspUrl))
        {
            // RFC 5280 §4.2.2.1. Without this extension nothing points a relying party at the
            // responder, so the OCSP endpoint would only ever be reached by someone told about it
            // out of band.
            accessDescriptions.Add(new AccessDescription(AccessDescription.IdADOcsp,
                new GeneralName(GeneralName.UniformResourceIdentifier, ocspUrl)));
        }
        if (!string.IsNullOrWhiteSpace(caIssuersUrl))
        {
            // Lets a client that holds only the leaf fetch the intermediate that signed it.
            accessDescriptions.Add(new AccessDescription(AccessDescription.IdADCAIssuers,
                new GeneralName(GeneralName.UniformResourceIdentifier, caIssuersUrl)));
        }
        if (accessDescriptions.Count == 1)
            certGen.AddExtension(X509Extensions.AuthorityInfoAccess, false, new AuthorityInformationAccess(accessDescriptions[0]));
        else if (accessDescriptions.Count > 1)
            certGen.AddExtension(X509Extensions.AuthorityInfoAccess, false,
                AuthorityInformationAccess.GetInstance(new DerSequence(accessDescriptions.ToArray<Asn1Encodable>())));

        if (template is not null)
        {
            var usages = DeserializeUsages(template.KeyUsagesJson);
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(strategy.BuildKeyUsageBits(usages)));
            AddEkuFromJson(certGen, template.ExtendedKeyUsagesJson);
        }
        else
        {
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(strategy.BuildKeyUsageBits([])));
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth));
        }

        var cdpUrl = urls is null ? caSettings?.CrlDistributionPoint : urls.CrlDistributionPoint;
        if (!string.IsNullOrWhiteSpace(cdpUrl))
        {
            var dpName = new DistributionPointName(new GeneralNames(
                new GeneralName(GeneralName.UniformResourceIdentifier, cdpUrl)));
            var dp = new DistributionPoint(dpName, null, null);
            certGen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint([dp]));
        }

        if (template is not null)
        {
            AddSanFromTemplate(certGen, request, template.SanTypesJson);
            if (!string.IsNullOrWhiteSpace(template.CustomExtensionsJson))
                AddCustomExtensions(certGen, template.CustomExtensionsJson);
        }
        else if (request.Type == "WebServer" && !string.IsNullOrWhiteSpace(request.PropertiesJson))
        {
            try
            {
                var props = JsonSerializer.Deserialize<WebServerProperties>(request.PropertiesJson, AppJsonOptions.Default);
                if (props != null && props.DnsNames.Count > 0)
                {
                    var names = new List<GeneralName> { new(GeneralName.DnsName, request.CommonName) };
                    names.AddRange(props.DnsNames
                        .Where(d => !string.Equals(d, request.CommonName, StringComparison.OrdinalIgnoreCase))
                        .Select(dns => new GeneralName(GeneralName.DnsName, dns)));
                    certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(names.ToArray()));
                }
            }
            catch (JsonException) { }
        }

        var cert = certGen.Generate(_caSigner!.CreateSignatureFactory());

        return new GeneratedCertificate
        {
            CertificatePem = QertumKeyCodec.WriteCertificatePem(cert),
            PrivateKeyPem = leafKeyPair is not null ? QertumKeyCodec.WritePrivateKeyPem(leafKeyPair.Private) : string.Empty,
            SerialNumber = serialNumber.ToString(16).ToUpperInvariant(),
            ValidFrom = validFrom,
            ValidTo = validTo
        };
    }


    private static List<string> DeserializeUsages(string keyUsagesJson)
    {
        try { return JsonSerializer.Deserialize<List<string>>(keyUsagesJson, AppJsonOptions.Default) ?? []; }
        catch (JsonException) { return []; }
    }

    private static void AddEkuFromJson(X509V3CertificateGenerator certGen, string ekuJson)
    {
        try
        {
            var oids = JsonSerializer.Deserialize<List<string>>(ekuJson, AppJsonOptions.Default) ?? [];
            var oidEncodables = oids
                .Where(o => !string.IsNullOrWhiteSpace(o))
                .Select<string, Asn1Encodable>(o => new DerObjectIdentifier(o))
                .ToArray();
            if (oidEncodables.Length > 0)
                certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new DerSequence(oidEncodables));
        }
        catch (JsonException) { }
    }

    private static void AddSanFromTemplate(X509V3CertificateGenerator certGen, CertificateRequest request, string sanTypesJson)
    {
        try
        {
            var sanTypes = JsonSerializer.Deserialize<List<string>>(sanTypesJson, AppJsonOptions.Default) ?? [];
            if (sanTypes.Count == 0 || string.IsNullOrWhiteSpace(request.PropertiesJson)) return;

            var props = JsonSerializer.Deserialize<CertificateProperties>(request.PropertiesJson, AppJsonOptions.Default);
            if (props is null) return;

            var names = new List<GeneralName>();

            if (sanTypes.Contains("dns"))
            {
                names.Add(new GeneralName(GeneralName.DnsName, request.CommonName));
                names.AddRange(props.DnsNames
                    .Where(d => !string.Equals(d, request.CommonName, StringComparison.OrdinalIgnoreCase))
                    .Select(dns => new GeneralName(GeneralName.DnsName, dns)));
            }

            if (sanTypes.Contains("ip"))
            {
                foreach (var ip in props.IpAddresses)
                {
                    if (IPAddress.TryParse(ip, out var parsed))
                        names.Add(new GeneralName(GeneralName.IPAddress, new DerOctetString(parsed.GetAddressBytes())));
                }
            }

            if (sanTypes.Contains("email"))
            {
                names.AddRange(props.EmailAddresses
                    .Where(e => !string.IsNullOrWhiteSpace(e))
                    .Select(email => new GeneralName(GeneralName.Rfc822Name, email)));
            }

            if (sanTypes.Contains("upn"))
            {
                var upnOid = new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.3");
                names.AddRange(props.UserPrincipalNames
                    .Where(u => !string.IsNullOrWhiteSpace(u))
                    .Select(upn => new GeneralName(GeneralName.OtherName,
                        new DerSequence(upnOid, new DerTaggedObject(true, 0, new DerUtf8String(upn))))));
            }

            if (names.Count > 0)
                certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(names.ToArray()));
        }
        catch (JsonException) { }
    }

    private static void AddCustomExtensions(X509V3CertificateGenerator certGen, string customExtensionsJson)
    {
        try
        {
            var extensions = JsonSerializer.Deserialize<List<CustomExtension>>(customExtensionsJson, AppJsonOptions.Default);
            if (extensions is null) return;
            foreach (var ext in extensions.Where(e => !string.IsNullOrWhiteSpace(e.Oid) && !string.IsNullOrWhiteSpace(e.Value)))
            {
                var oid = new DerObjectIdentifier(ext.Oid);
                certGen.AddExtension(oid, ext.Critical, new DerUtf8String(ext.Value));
            }
        }
        catch (JsonException) { }
    }

    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null)
        => GenerateCrl(revokedRequests, caSettings, crlNumber, thisUpdateUtc, urls: null);

    /// <inheritdoc />
    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings, long crlNumber, DateTime? thisUpdateUtc, Issuers.IssuerUrls? urls)
    {
        EnsureCaInitialized();

        var thisUpdate = thisUpdateUtc ?? _clock.GetUtcNow().UtcDateTime;
        var crlValidityHours = caSettings?.CrlValidityHours > 0 ? caSettings.CrlValidityHours : 24;
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(_caCertificate!.SubjectDN);
        crlGen.SetThisUpdate(thisUpdate);
        crlGen.SetNextUpdate(thisUpdate.AddHours(crlValidityHours));

        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            QertumKeyCodec.AuthorityKeyIdentifierFor(_caCertificate));

        // RFC 5280 §5.2.3. A monotonically increasing number is how a client decides which of two
        // cached CRLs is newer; some validators reject a CRL that lacks it outright.
        crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.ValueOf(crlNumber)));

        // RFC 5280 §5.2.6. Tells a delta-aware client where to find the smaller supplement to this
        // full CRL, so it need not re-download the whole (potentially PQC-signature-heavy) list on
        // every refresh. Only added when delta publishing is actually configured — an absent
        // extension is the correct signal that no delta exists.
        var deltaUrl = urls is null
            ? (caSettings?.DeltaCrlEnabled == true ? caSettings.CrlDeltaDistributionPoint : null)
            : urls.DeltaCrlDistributionPoint;
        if (!string.IsNullOrWhiteSpace(deltaUrl))
        {
            var dpName = new DistributionPointName(new GeneralNames(
                new GeneralName(GeneralName.UniformResourceIdentifier, deltaUrl)));
            crlGen.AddExtension(X509Extensions.FreshestCrl, false, new CrlDistPoint([new DistributionPoint(dpName, null, null)]));
        }

        AddRevokedEntries(crlGen, revokedRequests);

        return crlGen.Generate(_caSigner!.CreateSignatureFactory()).GetEncoded();
    }

    /// <inheritdoc cref="ICertificateGenerator.GenerateDeltaCrl"/>
    public byte[] GenerateDeltaCrl(
        IReadOnlyList<CertificateRequest> revokedSinceBase,
        CaSettings? caSettings,
        long crlNumber,
        long baseCrlNumber,
        DateTime? thisUpdateUtc = null)
    {
        EnsureCaInitialized();

        var thisUpdate = thisUpdateUtc ?? _clock.GetUtcNow().UtcDateTime;
        // A delta is meant to be refreshed often and cheaply, so its own validity window comes from
        // DeltaCrlValidityHours rather than the (typically much longer) full-CRL window.
        var validityHours = caSettings?.DeltaCrlValidityHours > 0 ? caSettings.DeltaCrlValidityHours : 6;
        var crlGen = new X509V2CrlGenerator();
        crlGen.SetIssuerDN(_caCertificate!.SubjectDN);
        crlGen.SetThisUpdate(thisUpdate);
        crlGen.SetNextUpdate(thisUpdate.AddHours(validityHours));

        crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
            QertumKeyCodec.AuthorityKeyIdentifierFor(_caCertificate));
        crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.ValueOf(crlNumber)));

        // RFC 5280 §5.2.4. Syntax is the same CRLNumber type as the CRL Number extension itself —
        // this is what tells a client which full CRL this delta is relative to.
        crlGen.AddExtension(X509Extensions.DeltaCrlIndicator, false, new CrlNumber(BigInteger.ValueOf(baseCrlNumber)));

        AddRevokedEntries(crlGen, revokedSinceBase);

        return crlGen.Generate(_caSigner!.CreateSignatureFactory()).GetEncoded();
    }

    private void AddRevokedEntries(X509V2CrlGenerator crlGen, IReadOnlyList<CertificateRequest> revokedRequests)
    {
        foreach (var cert in revokedRequests)
        {
            // A revoked pair is revoked as a whole: both certificates go on the CRL. The serials are
            // read from the PEMs rather than the stored columns so rows issued before
            // PqcSerialNumber existed are listed too.
            AddRevokedEntry(crlGen, cert, cert.CertificatePem);
            AddRevokedEntry(crlGen, cert, cert.PqcCertificatePem);
        }
    }

    private void AddRevokedEntry(X509V2CrlGenerator crlGen, CertificateRequest cert, string? certificatePem)
    {
        if (string.IsNullOrWhiteSpace(certificatePem)) return;
        try
        {
            var x509 = QertumKeyCodec.ReadCertificatePem(certificatePem)
                ?? throw new InvalidOperationException("The PEM holds no certificate.");
            var revokedAt = cert.RevokedAtUtc ?? _clock.GetUtcNow().UtcDateTime;
            crlGen.AddCrlEntry(x509.SerialNumber, revokedAt, MapRevocationReason(cert.RevocationReason));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Skipped revoked certificate {CertificateId} during CRL build: PEM could not be parsed.",
                cert.Id);
        }
    }

    /// <inheritdoc />
    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest)
    {
        var request = new OcspReq(derRequest);
        return [.. request.GetRequestList().Select(r => FormatSerial(r.GetCertID().SerialNumber))];
    }

    /// <inheritdoc />
    public byte[] GenerateOcspResponse(
        byte[] derRequest,
        IReadOnlyDictionary<string, OcspCertificateStatus> statuses,
        CaSettings? caSettings = null)
    {
        EnsureCaInitialized();

        var request = new OcspReq(derRequest);
        // byKey from the CA certificate's own SPKI: BouncyCastle's key-based constructor re-encodes
        // the key through its factory, which cannot encode a composite key.
        var responseGenerator = new BasicOcspRespGenerator(QertumKeyCodec.ResponderIdByKey(_caCertificate!));

        var now = _clock.GetUtcNow().UtcDateTime;
        // A response is only as fresh as the revocation data behind it, and that data is the same
        // set the CRL publishes, so the two agree on how long an answer may be cached.
        var validityHours = caSettings?.CrlValidityHours > 0 ? caSettings.CrlValidityHours : 24;
        var nextUpdate = now.AddHours(validityHours);

        foreach (var singleRequest in request.GetRequestList())
        {
            var certId = singleRequest.GetCertID();
            var serial = FormatSerial(certId.SerialNumber);

            // A CertID naming some other issuer is not ours to answer for, and neither is a serial we
            // have no record of. Both are "unknown" rather than "good": answering good for a serial
            // this CA never issued would vouch for a certificate that does not exist.
            var status = !certId.MatchesIssuer(_caCertificate!) || !statuses.TryGetValue(serial, out var found)
                ? OcspCertificateStatus.Unknown
                : found;

            responseGenerator.AddResponse(certId, ToBouncyCastleStatus(status), now, nextUpdate, null);
        }

        // RFC 6960 §4.4.1: a client that sent a nonce needs it echoed back, otherwise it cannot tell
        // this response from a replayed one.
        var nonce = request.RequestExtensions?.GetExtension(OcspObjectIdentifiers.PkixOcspNonce);
        if (nonce is not null)
        {
            responseGenerator.SetResponseExtensions(new X509Extensions(
                new Dictionary<DerObjectIdentifier, X509Extension>
                {
                    [OcspObjectIdentifiers.PkixOcspNonce] = nonce
                }));
        }

        // The CA signs its own responses, so the chain carries the CA certificate itself rather than
        // a delegated responder certificate.
        var basicResponse = responseGenerator.Generate(_caSigner!.CreateSignatureFactory(), [_caCertificate!], now);

        return new OCSPRespGenerator().Generate(OcspRespStatus.Successful, basicResponse).GetEncoded();
    }

    /// <summary>
    /// Builds the DER response body that reports a request as unusable. RFC 6960 §2.3 answers a
    /// malformed request with an OCSP response carrying that status, not with a transport error, and
    /// such a response is unsigned by definition.
    /// </summary>
    public static byte[] GenerateOcspMalformedRequestResponse() =>
        new OCSPRespGenerator().Generate(OcspRespStatus.MalformedRequest, null).GetEncoded();

    private Org.BouncyCastle.Ocsp.CertificateStatus ToBouncyCastleStatus(OcspCertificateStatus status) =>
        status.State switch
        {
            OcspCertificateState.Good => Org.BouncyCastle.Ocsp.CertificateStatus.Good,
            OcspCertificateState.Revoked => new RevokedStatus(
                status.RevokedAtUtc ?? _clock.GetUtcNow().UtcDateTime,
                MapRevocationReason(status.RevocationReason)),
            _ => new UnknownStatus()
        };

    /// <summary>
    /// Serials are stored as uppercase hex without a leading zero (see
    /// <see cref="BuildSingleCertificate"/>), so lookups have to be formatted the same way.
    /// </summary>
    private static string FormatSerial(BigInteger serial) => serial.ToString(16).ToUpperInvariant();

    /// <summary>
    /// Maps the stored free-text revocation reason onto an RFC 5280 CRL reason code.
    /// The reason is operator-typed (or the literal "superseded" written by AutoRevokeOnRenewal), so
    /// matching is case-insensitive and tolerates spaces and hyphens. Anything unrecognized stays
    /// <see cref="CrlReason.Unspecified"/>, which is the correct code for "reason not given".
    /// </summary>
    internal static int MapRevocationReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason))
            return CrlReason.Unspecified;

        var normalized = reason.Replace(" ", string.Empty).Replace("-", string.Empty).Replace("_", string.Empty);

        return normalized.ToLowerInvariant() switch
        {
            "keycompromise" => CrlReason.KeyCompromise,
            "cacompromise" => CrlReason.CACompromise,
            "affiliationchanged" => CrlReason.AffiliationChanged,
            "superseded" => CrlReason.Superseded,
            "cessationofoperation" => CrlReason.CessationOfOperation,
            "certificatehold" => CrlReason.CertificateHold,
            "removefromcrl" => CrlReason.RemoveFromCrl,
            "privilegewithdrawn" => CrlReason.PrivilegeWithdrawn,
            "aacompromise" => CrlReason.AACompromise,
            _ => CrlReason.Unspecified
        };
    }

    public string GetCaCertificatePem()
    {
        EnsureCaInitialized();
        return File.ReadAllText(Path.Combine(_caDataDirectory, "ca.pem"));
    }

    public CaStatusResponse GetCaStatus()
    {
        if (_caCertificate != null && _caSigner != null)
            return BuildStatusFromCert(_caCertificate);

        var caCertPath = Path.Combine(_caDataDirectory, "ca.pem");
        var caKeyPath = Path.Combine(_caDataDirectory, "ca.key");

        if (!File.Exists(caCertPath) || !File.Exists(caKeyPath))
            return new CaStatusResponse { IsInitialized = false };

        try
        {
            var cert = QertumKeyCodec.ReadCertificatePem(File.ReadAllText(caCertPath))
                ?? throw new InvalidOperationException("ca.pem holds no certificate.");
            return BuildStatusFromCert(cert);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "CA certificate exists on disk but could not be parsed.");
            return new CaStatusResponse { IsInitialized = true };
        }
    }

    /// <summary>
    /// Whether <paramref name="certificate"/>'s EC key spells out its curve instead of naming it
    /// (RFC 5480 §2.1.1 requires the name; OpenSSL 3 refuses the other form in a chain).
    /// </summary>
    internal static bool UsesExplicitCurveParameters(X509Certificate certificate)
    {
        var algorithm = certificate.SubjectPublicKeyInfo.Algorithm;
        return algorithm.Algorithm.Equals(Org.BouncyCastle.Asn1.X9.X9ObjectIdentifiers.IdECPublicKey) &&
               algorithm.Parameters?.ToAsn1Object() is Org.BouncyCastle.Asn1.Asn1Sequence;
    }

    private static CaStatusResponse BuildStatusFromCert(X509Certificate cert)
    {
        var dn = cert.SubjectDN;
        return new CaStatusResponse
        {
            IsInitialized = true,
            SubjectDn = dn.ToString(),
            ValidFrom = cert.NotBefore,
            ValidTo = cert.NotAfter,
            // Null rather than a guess when the key is not one this CA issues for — the status
            // banner showing nothing is better than it naming the wrong algorithm.
            Algorithm = GetAlgorithmFromPublicKey(QertumKeyCodec.PublicKeyOf(cert))?.ToCanonicalString(),
            ExplicitCurveParameters = UsesExplicitCurveParameters(cert),
            CaCommonName = GetDnField(dn, X509Name.CN),
            OrganizationName = GetDnField(dn, X509Name.O),
            OrganizationalUnit = GetDnField(dn, X509Name.OU),
            Country = GetDnField(dn, X509Name.C),
            State = GetDnField(dn, X509Name.ST),
            Locality = GetDnField(dn, X509Name.L)
        };
    }

    /// <summary>
    /// A 159-bit CSPRNG serial: positive, and at most the 20 octets RFC 5280 §4.1.2.2 allows once DER
    /// encoding adds no sign byte. The entropy is what makes the serial unpredictable (a CA/Browser
    /// Forum requirement, and the defence against hash-collision forgery); primality would add cost
    /// and nothing else, which is why this is not <c>BigInteger.ProbablePrime</c>. Uniqueness is
    /// enforced where it can actually be guaranteed — the unique index on
    /// <see cref="CertificateRequest.SerialNumber"/> — not by a check here.
    /// </summary>
    internal static BigInteger GenerateSerialNumber(SecureRandom random) => new(159, random);

    private static string? GetDnField(X509Name dn, DerObjectIdentifier oid)
    {
        var values = dn.GetValueList(oid);
        return values.Count > 0 ? (string?)values[0] : null;
    }

    public GeneratedCertificate GenerateCa(GenerateCaRequest request)
    {
        lock (_initLock)
        {
            var caKeyPath = Path.Combine(_caDataDirectory, "ca.key");
            var caCertPath = Path.Combine(_caDataDirectory, "ca.pem");

            if (File.Exists(caKeyPath) || File.Exists(caCertPath))
                throw new InvalidOperationException("A CA certificate already exists. Remove existing CA files to regenerate.");

            var random = new SecureRandom();
            var algorithm = request.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
            var strategy = AlgorithmStrategyFactory.CreateIssuer(algorithm);
            var keyPair = strategy.GenerateCaKeyPair(random);

            var subjectName = Issuers.CaCertificateBuilder.SubjectName(request.CommonName, request.OrganizationName,
                request.OrganizationalUnit, request.Country, request.State, request.Locality);
            var validityDays = request.ValidityDays > 0 ? request.ValidityDays : 3650;
            var now = _clock.GetUtcNow().UtcDateTime;
            // Self-signed through the same seam as every other signature, so the root is produced the
            // way the CA will go on producing certificates rather than by a one-off path.
            var rootSigner = _caSignerFactory(keyPair);
            var cert = Issuers.CaCertificateBuilder.BuildRoot(rootSigner, subjectName, now.AddMinutes(-5), now.AddDays(validityDays));
            var serialNumber = cert.SerialNumber;
            var notBefore = cert.NotBefore.ToUniversalTime();
            var notAfter = cert.NotAfter.ToUniversalTime();
            var certPem = QertumKeyCodec.WriteCertificatePem(cert);

            Directory.CreateDirectory(Path.GetDirectoryName(caCertPath)!);
            File.WriteAllText(caCertPath, certPem);
            File.WriteAllText(caKeyPath, _keyProtector.Protect(QertumKeyCodec.WritePrivateKeyPem(keyPair.Private)));

            _caSigner = rootSigner;
            _caCertificate = cert;

            if (_logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Root CA generated with subject {SubjectDN}.", subjectName);

            // PrivateKeyPem is intentionally empty: the CA key stays in the encrypted on-disk file only.
            return new GeneratedCertificate
            {
                CertificatePem = certPem,
                PrivateKeyPem = string.Empty,
                SerialNumber = serialNumber.ToString(16).ToUpperInvariant(),
                ValidFrom = notBefore,
                ValidTo = notAfter
            };
        }
    }

    /// <summary>This CA's certificate (loads the CA files on first use).</summary>
    public X509Certificate CaCertificate
    {
        get { EnsureCaInitialized(); return _caCertificate!; }
    }

    /// <inheritdoc />
    public X509Certificate IssueSubordinateCa(SubjectPublicKeyInfo subjectKey, X509Name subject,
        Issuers.SubordinateCaProfile profile, DateTime notAfter, Issuers.IssuerUrls? urls)
    {
        EnsureCaInitialized();
        var notBefore = _clock.GetUtcNow().UtcDateTime.AddMinutes(-5);
        // A CA certificate may not outlive the CA that signed it.
        var cappedNotAfter = notAfter > _caCertificate!.NotAfter.ToUniversalTime() ? _caCertificate.NotAfter.ToUniversalTime() : notAfter;
        return Issuers.CaCertificateBuilder.IssueSubordinate(_caSigner!, _caCertificate, subjectKey, subject, profile,
            notBefore, cappedNotAfter, urls);
    }

    public void ImportCa(ImportCaRequest request)
    {
        lock (_initLock)
        {
            var caKeyPath = Path.Combine(_caDataDirectory, "ca.key");
            var caCertPath = Path.Combine(_caDataDirectory, "ca.pem");

            if (File.Exists(caKeyPath) || File.Exists(caCertPath))
                throw new InvalidOperationException("A CA certificate already exists. Remove existing CA files to replace the CA.");

            X509Certificate? cert;
            try
            {
                cert = QertumKeyCodec.ReadCertificatePem(request.CertificatePem);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("The certificate PEM could not be parsed.", nameof(request), ex);
            }

            if (cert is null)
                throw new ArgumentException("The certificate PEM could not be parsed.", nameof(request));

            var bcExt = cert.GetExtensionValue(X509Extensions.BasicConstraints);
            if (bcExt != null)
            {
                var bc = BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(bcExt));
                if (!bc.IsCA())
                    throw new ArgumentException("The provided certificate is not a CA certificate (BasicConstraints.cA is false).", nameof(request));
            }

            AsymmetricCipherKeyPair keyPair;
            try
            {
                var privateKey = QertumKeyCodec.ReadPrivateKeyPem(request.PrivateKeyPem);
                keyPair = new AsymmetricCipherKeyPair(QertumKeyCodec.PublicKeyFromPrivate(privateKey), privateKey);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException("Unrecognised private key format in the provided PEM.", nameof(request), ex);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("The private key PEM could not be parsed.", nameof(request), ex);
            }

            if (!QertumKeyCodec.IsMatchingPair(keyPair.Private, QertumKeyCodec.PublicKeyOf(cert)))
                throw new ArgumentException("The private key does not correspond to the certificate's public key.");

            Directory.CreateDirectory(Path.GetDirectoryName(caCertPath)!);
            File.WriteAllText(caCertPath, request.CertificatePem.Trim() + Environment.NewLine);
            File.WriteAllText(caKeyPath, _keyProtector.Protect(QertumKeyCodec.WritePrivateKeyPem(keyPair.Private)));

            _caSigner = _caSignerFactory(keyPair);
            _caCertificate = cert;

            if (_logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("CA certificate imported with subject {SubjectDN}.", cert.SubjectDN);
        }
    }

    private void EnsureCaInitialized()
    {
        if (_caSigner != null && _caCertificate != null) return;
        lock (_initLock)
        {
            if (_caSigner != null && _caCertificate != null) return;

            var caKeyPath = Path.Combine(_caDataDirectory, "ca.key");
            var caCertPath = Path.Combine(_caDataDirectory, "ca.pem");

            if (!File.Exists(caKeyPath) || !File.Exists(caCertPath))
                throw new InvalidOperationException(
                    "CA certificate not initialized. Complete the CA setup at /onboarding before issuing certificates.");

            _caCertificate = QertumKeyCodec.ReadCertificatePem(File.ReadAllText(caCertPath))
                ?? throw new InvalidOperationException("ca.pem holds no certificate.");

            var keyPem = DecryptCaKeyOrPassThrough(File.ReadAllText(caKeyPath));
            AsymmetricKeyParameter privateKey;
            try
            {
                privateKey = QertumKeyCodec.ReadPrivateKeyPem(keyPem);
            }
            catch (ArgumentException ex)
            {
                throw new InvalidOperationException("Unrecognised CA key format in ca.key.", ex);
            }

            // The public key comes from the already-loaded CA certificate, for every algorithm.
            _caSigner = _caSignerFactory(new AsymmetricCipherKeyPair(QertumKeyCodec.PublicKeyOf(_caCertificate), privateKey));
        }
    }


    private string DecryptCaKeyOrPassThrough(string stored)
    {
        // Legacy files written before encryption was introduced start with -----BEGIN
        if (stored.StartsWith("-----BEGIN", StringComparison.Ordinal))
            return stored;
        try
        {
            return _keyProtector.Unprotect(stored);
        }
        catch (CryptographicException)
        {
            // Corrupted or tampered; surface the error rather than silently ignoring
            throw new InvalidOperationException("CA private key could not be decrypted. The Data Protection key ring may have changed.");
        }
    }

    /// <summary>
    /// Maps a public key to the <see cref="CertificateKeyAlgorithm"/> Qertum would issue it under,
    /// or <see langword="null"/> when there is no such value. Every match is exact: the result is
    /// persisted as a request's <c>KeyAlgorithm</c> and selects the issuing
    /// <see cref="ICertificateAlgorithmStrategy"/>, so a near-miss (an ML-DSA-44 key reported as
    /// ML-DSA-65, an Ed25519 key reported as RSA) would put a certificate on record under an
    /// algorithm it does not have — and, for a classical fallback, stamp key-encipherment usage
    /// onto a signature-only key. Callers turn <see langword="null"/> into a rejection.
    /// </summary>
    private static CertificateKeyAlgorithm? GetAlgorithmFromPublicKey(AsymmetricKeyParameter key) =>
        key switch
        {
            Crypto.Composite.CompositePublicKey composite => Crypto.Composite.CompositeAlgorithms.ToKeyAlgorithm(composite.Algorithm),
            MLDsaPublicKeyParameters mlDsaKey =>
                mlDsaKey.Parameters == MLDsaParameters.ml_dsa_44 ? CertificateKeyAlgorithm.MlDsa44
                : mlDsaKey.Parameters == MLDsaParameters.ml_dsa_65 ? CertificateKeyAlgorithm.MlDsa65
                : mlDsaKey.Parameters == MLDsaParameters.ml_dsa_87 ? CertificateKeyAlgorithm.MlDsa87
                : null,
            SlhDsaPublicKeyParameters slhDsaKey =>
                slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_128s ? CertificateKeyAlgorithm.SlhDsaSha2128s
                : slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_128f ? CertificateKeyAlgorithm.SlhDsaSha2128f
                : slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_192s ? CertificateKeyAlgorithm.SlhDsaSha2192s
                : slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_192f ? CertificateKeyAlgorithm.SlhDsaSha2192f
                : slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_256s ? CertificateKeyAlgorithm.SlhDsaSha2256s
                : slhDsaKey.Parameters == SlhDsaParameters.slh_dsa_sha2_256f ? CertificateKeyAlgorithm.SlhDsaSha2256f
                : null,
            MLKemPublicKeyParameters mlKemKey =>
                mlKemKey.Parameters == MLKemParameters.ml_kem_512 ? CertificateKeyAlgorithm.MlKem512
                : mlKemKey.Parameters == MLKemParameters.ml_kem_768 ? CertificateKeyAlgorithm.MlKem768
                : mlKemKey.Parameters == MLKemParameters.ml_kem_1024 ? CertificateKeyAlgorithm.MlKem1024
                : null,
            ECPublicKeyParameters ecKey => MatchNamedCurve(ecKey),
            RsaKeyParameters => CertificateKeyAlgorithm.Rsa,
            _ => null
        };

    /// <summary>
    /// Matches an EC key against the two curves Qertum supports by comparing the curve itself, not
    /// its order's bit length — a length test lumps every curve of that size (and everything
    /// larger, such as P-521) in with the one named value.
    /// </summary>
    private static CertificateKeyAlgorithm? MatchNamedCurve(ECPublicKeyParameters key)
    {
        foreach (var (name, algorithm) in SupportedCurves)
        {
            var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(name);
            if (curve is not null &&
                key.Parameters.Curve.Equals(curve.Curve) &&
                key.Parameters.N.Equals(curve.N))
            {
                return algorithm;
            }
        }

        return null;
    }

    private static readonly (string Name, CertificateKeyAlgorithm Algorithm)[] SupportedCurves =
    [
        ("P-256", CertificateKeyAlgorithm.EcdsaP256),
        ("P-384", CertificateKeyAlgorithm.EcdsaP384)
    ];

    private static CertificateKeyAlgorithm RequireSupportedAlgorithm(AsymmetricKeyParameter key) =>
        GetAlgorithmFromPublicKey(key)
        ?? throw new NotSupportedException(
            $"The key type '{key.GetType().Name}' is not an algorithm this CA can issue for. " +
            "Supported: RSA, ECDSA-P256, ECDSA-P384, ML-DSA, SLH-DSA-SHA2 (128, 192, 256; S/F), composite ML-DSA and ML-KEM.");

    /// <summary>
    /// Parses a PKCS#10 CSR (base64url DER, as ACME clients send it) and returns the
    /// <see cref="CertificateKeyAlgorithm"/> matching its public key. Used to check the PQC enforcement stage
    /// issuance policy against the key the client actually generated, not a caller-supplied enum.
    /// </summary>
    public static CertificateKeyAlgorithm DetectAlgorithmFromCsr(string csrDerBase64Url)
    {
        var csrBytes = Base64UrlText.Decode(csrDerBase64Url);
        var csr = new Pkcs10CertificationRequest(csrBytes);
        if (!QertumKeyCodec.VerifySelfSignature(csr))
            throw new ArgumentException("CSR signature verification failed.");

        return RequireSupportedAlgorithm(QertumKeyCodec.PublicKeyOf(csr));
    }

    /// <summary>
    /// Parses a certificate PEM and returns the <see cref="CertificateKeyAlgorithm"/> matching its
    /// public key. Used to check the PQC enforcement stage against an imported CA certificate
    /// before its files are written.
    /// </summary>
    public static CertificateKeyAlgorithm DetectAlgorithmFromCertificatePem(string certificatePem)
    {
        X509Certificate? cert;
        try
        {
            cert = QertumKeyCodec.ReadCertificatePem(certificatePem);
        }
        catch (Exception ex)
        {
            throw new ArgumentException("The certificate PEM could not be parsed.", nameof(certificatePem), ex);
        }

        if (cert is null)
            throw new ArgumentException("The certificate PEM could not be parsed.", nameof(certificatePem));

        return RequireSupportedAlgorithm(QertumKeyCodec.PublicKeyOf(cert));
    }

}
