using System.Security.Cryptography;
using Org.BouncyCastle.X509;
using Qertum.Services.Crypto;

namespace Qertum.Cli.Doctor;

/// <summary>
/// Certificate helpers on BouncyCastle through <see cref="QertumKeyCodec"/>, the code the server verifies
/// with, so ML-DSA, SLH-DSA and composite certificates verify on platforms whose BCL cannot.
/// </summary>
internal static class DoctorCerts
{
    /// <summary>Every certificate in a PEM or DER blob; empty when it holds none or is not a certificate file.</summary>
    public static IReadOnlyList<X509Certificate> ParseBundle(byte[] bytes)
    {
        var certificates = new List<X509Certificate>();
        try
        {
            foreach (X509Certificate certificate in new X509CertificateParser().ReadCertificates(new MemoryStream(bytes)))
                certificates.Add(certificate);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Not a certificate file: the caller reports "no certificate".
            return [];
        }

        return certificates;
    }

    public static bool VerifiesWith(X509Certificate certificate, X509Certificate issuer)
    {
        try
        {
            certificate.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(issuer)));
            return true;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return false;
        }
    }

    public static bool IsSelfSigned(X509Certificate certificate) =>
        certificate.IssuerDN.Equivalent(certificate.SubjectDN) && VerifiesWith(certificate, certificate);

    public static string Sha256(X509Certificate certificate) =>
        Convert.ToHexString(SHA256.HashData(certificate.GetEncoded())).ToLowerInvariant();

    public static string Name(X509Certificate certificate)
    {
        var cn = certificate.SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN);
        return cn.Count > 0 ? cn[0]?.ToString() ?? certificate.SubjectDN.ToString() : certificate.SubjectDN.ToString();
    }
}
