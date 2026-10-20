namespace Qertum.Services;

public interface ICertificateGenerator
{
    /// <summary>True when the CA key and certificate files exist on disk.</summary>
    bool IsInitialized { get; }

    GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null);

    /// <summary>As the overload without <paramref name="urls"/>, writing <paramref name="urls"/> instead of CaSettings' URLs when non-null.</summary>
    GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template, Issuers.IssuerUrls? urls)
        => GenerateCertificate(request, caSettings, template);

    /// <summary>
    /// Issues a certificate using the public key from a PKCS#10 CSR instead of generating a new key pair.
    /// The returned <see cref="GeneratedCertificate.PrivateKeyPem"/> is empty — the private key is held by the ACME client.
    /// Hybrid/PQC algorithms are not supported; pass RSA or ECDSA requests only.
    /// </summary>
    GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null);

    /// <summary>As the overload without <paramref name="urls"/>, writing <paramref name="urls"/> instead of CaSettings' URLs when non-null.</summary>
    GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template, Issuers.IssuerUrls? urls)
        => GenerateFromCsr(csrDerBase64Url, request, caSettings, template);

    /// <param name="crlNumber">
    /// Value for the RFC 5280 CRL number extension. Must increase with every CRL this CA publishes, so
    /// the caller claims it from persistent storage rather than the generator deriving it.
    /// </param>
    byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null);

    /// <summary>As the overload without <paramref name="urls"/>, taking the FreshestCrl URL from <paramref name="urls"/> when non-null.</summary>
    byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings, long crlNumber, DateTime? thisUpdateUtc, Issuers.IssuerUrls? urls)
        => GenerateCrl(revokedRequests, caSettings, crlNumber, thisUpdateUtc);

    /// <summary>
    /// Builds a delta CRL (RFC 5280 §5.2.4) containing only <paramref name="revokedSinceBase"/> —
    /// the certificates revoked after the base CRL identified by <paramref name="baseCrlNumber"/>
    /// was published. <paramref name="crlNumber"/> must be greater than every CRL number issued so
    /// far, base or delta — RFC 5280 does not give deltas their own number space.
    /// </summary>
    byte[] GenerateDeltaCrl(
        IReadOnlyList<CertificateRequest> revokedSinceBase,
        CaSettings? caSettings,
        long crlNumber,
        long baseCrlNumber,
        DateTime? thisUpdateUtc = null);

    /// <summary>
    /// Reads the serial numbers a DER-encoded OCSP request asks about, as uppercase hex matching
    /// <see cref="CertificateRequest.SerialNumber"/>. Serials whose CertID names a different issuer
    /// are still returned — the caller will find no row for them and the responder reports
    /// <see cref="OcspCertificateState.Unknown"/>, which is the correct answer for "not ours".
    /// Throws <see cref="System.IO.IOException"/> or <see cref="ArgumentException"/> on a malformed request.
    /// </summary>
    IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest);

    /// <summary>
    /// Builds a signed OCSP response for <paramref name="derRequest"/>. The statuses come from the
    /// caller — the generator never reads the database, the same split the CRL number uses.
    /// Serials absent from <paramref name="statuses"/> are reported as unknown.
    /// </summary>
    byte[] GenerateOcspResponse(
        byte[] derRequest,
        IReadOnlyDictionary<string, OcspCertificateStatus> statuses,
        CaSettings? caSettings = null);

    CaStatusResponse GetCaStatus();

    /// <summary>Returns the raw PEM text of the current root CA certificate. Throws if CA is not initialized.</summary>
    string GetCaCertificatePem();

    /// <summary>
    /// Generates a new self-signed root CA key and certificate, writes them to disk, and
    /// returns a <see cref="GeneratedCertificate"/> with the public certificate PEM and
    /// validity dates. <see cref="GeneratedCertificate.PrivateKeyPem"/> is empty — the CA
    /// private key is stored only in the encrypted on-disk file, not in the database.
    /// </summary>
    GeneratedCertificate GenerateCa(GenerateCaRequest request);

    void ImportCa(ImportCaRequest request);

    /// <summary>
    /// Signs a subordinate CA certificate for <paramref name="subjectKey"/> with this CA's key. The
    /// default throws <see cref="NotSupportedException"/>; <see cref="CertificateGenerator"/> signs.
    /// </summary>
    Org.BouncyCastle.X509.X509Certificate IssueSubordinateCa(Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo subjectKey,
        Org.BouncyCastle.Asn1.X509.X509Name subject, Issuers.SubordinateCaProfile profile, DateTime notAfter, Issuers.IssuerUrls? urls)
        => throw new NotSupportedException("This CA backend cannot sign a subordinate CA.");
}
