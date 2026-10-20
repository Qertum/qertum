using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Qertum.Services.Crypto;

namespace Qertum.Services.Est;

/// <summary>
/// Reads the subject CN and DNS SANs out of a CSR. Unlike ACME's <c>finalize</c> handler — which
/// deliberately ignores the CSR's subject because the order's already-validated identifiers are
/// authoritative — EST has no domain-validation step, so the CSR's own subject/SAN is the identity
/// (RFC 7030 has nothing equivalent to http-01/dns-01).
/// </summary>
public static class EstCsrHelper
{
    /// <summary>
    /// Decodes the base64url DER CSR body EST endpoints receive, verifies its self-signature, and
    /// returns its subject common name plus any DNS names from a SubjectAlternativeName extension
    /// request attribute. Throws <see cref="ArgumentException"/> if the CSR is malformed, unsigned
    /// correctly, or carries no CN.
    /// </summary>
    public static (string CommonName, IReadOnlyList<string> DnsNames) ExtractIdentity(string csrDerBase64Url)
    {
        var csrBytes = Base64UrlText.Decode(csrDerBase64Url);
        var csr = new Pkcs10CertificationRequest(csrBytes);
        if (!QertumKeyCodec.VerifySelfSignature(csr))
            throw new ArgumentException("CSR signature verification failed.");

        var info = csr.GetCertificationRequestInfo();
        var cnValues = info.Subject.GetValueList(X509Name.CN);
        if (cnValues.Count == 0)
            throw new ArgumentException("CSR subject has no Common Name.");
        var commonName = (string)cnValues[0];

        var dnsNames = new List<string>();
        if (info.Attributes is not null)
        {
            foreach (var attrObj in info.Attributes)
            {
                var attr = AttributePkcs.GetInstance(attrObj);
                if (!attr.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest)) continue;

                var extensions = X509Extensions.GetInstance(attr.AttrValues[0]);
                var sanExtension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                if (sanExtension is null) continue;

                var generalNames = GeneralNames.GetInstance(sanExtension.GetParsedValue());
                dnsNames.AddRange(generalNames.GetNames()
                    .Where(n => n.TagNo == GeneralName.DnsName)
                    .Select(n => n.Name.ToString()!));
            }
        }

        return (commonName, dnsNames);
    }
}
