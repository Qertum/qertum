using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Qertum.Tests;

/// <summary>Shared self-signed certificate factory for tests. Keep this the single source rather
/// than each test file inlining its own RSA <see cref="CertificateRequest"/> boilerplate.</summary>
internal static class TestCertificates
{
    public static X509Certificate2 CreateSelfSigned(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));
    }

    /// <summary>
    /// A self-signed Ed25519 certificate, as PEM. Built with BouncyCastle because
    /// <see cref="CertificateRequest"/> has no Ed25519 overload. Used to exercise the paths that
    /// must refuse a key type Qertum has no <c>CertificateKeyAlgorithm</c> for.
    /// </summary>
    public static string CreateSelfSignedEd25519Pem(string subjectDn)
    {
        var random = new SecureRandom();
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(random));
        var keyPair = gen.GenerateKeyPair();

        var name = new X509Name(subjectDn);
        var certGen = new X509V3CertificateGenerator();
        certGen.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
        certGen.SetIssuerDN(name);
        certGen.SetSubjectDN(name);
        certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certGen.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGen.SetPublicKey(keyPair.Public);
        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));

        var cert = certGen.Generate(new Asn1SignatureFactory("Ed25519", keyPair.Private, random));

        using var sw = new StringWriter();
        new Org.BouncyCastle.OpenSsl.PemWriter(sw).WriteObject(cert);
        return sw.ToString();
    }
}
