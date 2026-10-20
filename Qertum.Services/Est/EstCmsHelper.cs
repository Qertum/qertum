using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Qertum.Services.Est;

/// <summary>
/// Builds and parses the "degenerate" PKCS#7 <c>SignedData</c> message RFC 7030 uses to wrap
/// certificates (§4.1.1, §4.1.3, §4.2.2): certs-only, no signer info. Nothing else in Qertum emits
/// PKCS#7 — ACME and the CLI both move certificates as PEM.
/// </summary>
public static class EstCmsHelper
{
    /// <summary>Builds a base64-encoded degenerate CMS SignedData containing the given certificates, in order.</summary>
    public static string BuildDegenerateCmsBase64(IReadOnlyList<X509Certificate2> certificates)
    {
        var bcCerts = certificates
            .Select(c => new X509CertificateParser().ReadCertificate(c.RawData))
            .ToList();

        var generator = new CmsSignedDataGenerator();
        generator.AddCertificates(CollectionUtilities.CreateStore(bcCerts));

        // No signer: RFC 7030's degenerate form has no content and no signature, only the
        // certificate bag. `content: null` throws (BouncyCastle.Cryptography 2.7.0 requires a
        // non-null CmsTypedData); `encapsulate: false` with an empty CmsProcessableByteArray is
        // what actually produces SignedData with an absent (not empty) eContent.
        var signedData = generator.Generate(new CmsProcessableByteArray([]), encapsulate: false);
        return Convert.ToBase64String(signedData.GetEncoded("DER"));
    }

    /// <summary>Parses a base64-encoded degenerate CMS SignedData back into its certificates, in order.</summary>
    public static IReadOnlyList<X509Certificate2> ParseDegenerateCms(string base64)
    {
        var der = Convert.FromBase64String(base64);
        var cms = new CmsSignedData(der);
        var store = cms.GetCertificates();

        return store.EnumerateMatches(null)
            .Cast<BcX509Certificate>()
            .Select(c => X509CertificateLoader.LoadCertificate(c.GetEncoded()))
            .ToList();
    }
}
