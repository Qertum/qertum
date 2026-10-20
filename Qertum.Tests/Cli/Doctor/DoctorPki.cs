using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Qertum.Tests.Cli.Doctor;

/// <summary>A small ECDSA P-256 PKI built with BouncyCastle: roots, intermediates, PEM and CRLs.</summary>
internal sealed class DoctorPki
{
    private static readonly SecureRandom Random = new();

    public required AsymmetricCipherKeyPair Key { get; init; }

    public required X509Certificate Certificate { get; init; }

    public static AsymmetricCipherKeyPair NewKey()
    {
        var generator = new ECKeyPairGenerator();
        generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));
        return generator.GenerateKeyPair();
    }

    /// <summary>A certificate for <paramref name="subjectKey"/> signed by <paramref name="issuerKey"/>; self-signed when subject and issuer match.</summary>
    public static X509Certificate Issue(string subjectCn, AsymmetricCipherKeyPair subjectKey, string issuerCn, AsymmetricCipherKeyPair issuerKey,
        DateTime notBefore, DateTime notAfter, bool ca = true)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.ProbablePrime(62, Random));
        generator.SetIssuerDN(new X509Name($"CN={issuerCn}"));
        generator.SetSubjectDN(new X509Name($"CN={subjectCn}"));
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(subjectKey.Public);
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", issuerKey.Private, Random));
    }

    public static DoctorPki Root(string cn, DateTime notBefore, DateTime notAfter)
    {
        var key = NewKey();
        return new DoctorPki { Key = key, Certificate = Issue(cn, key, cn, key, notBefore, notAfter) };
    }

    public DoctorPki Intermediate(string cn, DateTime notBefore, DateTime notAfter)
    {
        var key = NewKey();
        var issuerCn = Certificate.SubjectDN.GetValueList(X509Name.CN)[0]!.ToString()!;
        return new DoctorPki { Key = key, Certificate = Issue(cn, key, issuerCn, Key, notBefore, notAfter) };
    }

    public static string Pem(params X509Certificate[] certificates)
    {
        var text = new StringBuilder();
        foreach (var certificate in certificates)
        {
            text.AppendLine("-----BEGIN CERTIFICATE-----");
            text.AppendLine(Convert.ToBase64String(certificate.GetEncoded(), Base64FormattingOptions.InsertLineBreaks));
            text.AppendLine("-----END CERTIFICATE-----");
        }

        return text.ToString();
    }

    /// <summary>A DER CRL for this issuer, signed with <paramref name="signingKey"/> (defaults to the issuer's own key).</summary>
    public byte[] Crl(DateTime thisUpdate, DateTime? nextUpdate, AsymmetricCipherKeyPair? signingKey = null)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(Certificate.SubjectDN);
        generator.SetThisUpdate(thisUpdate);
        if (nextUpdate is { } next) generator.SetNextUpdate(next);
        return generator.Generate(new Asn1SignatureFactory("SHA256WITHECDSA", (signingKey ?? Key).Private, Random)).GetEncoded();
    }
}
