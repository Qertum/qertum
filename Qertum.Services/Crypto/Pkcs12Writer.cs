using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ContentInfo = Org.BouncyCastle.Asn1.Pkcs.ContentInfo;

namespace Qertum.Services.Crypto;

/// <summary>
/// Writes a PKCS#12 file from parts, so any key <see cref="QertumKeyCodec"/> can express as a
/// <c>PrivateKeyInfo</c> can be exported — BouncyCastle's <c>Pkcs12Store</c> builds that structure
/// through its own factory and cannot hold a composite key. Protection is what current Windows,
/// OpenSSL 3 and Java accept: the key in a PBES2 (PBKDF2-HMAC-SHA-256, AES-256-CBC) shrouded bag,
/// certificates in a plain bag, and an HMAC-SHA-256 MAC over the whole. <c>localKeyId</c> and
/// <c>friendlyName</c> pair the key with its certificate, which Windows needs to import the two together.
/// </summary>
internal static class Pkcs12Writer
{
    internal const int Iterations = 100_000;

    public static byte[] Write(X509Certificate leaf, PrivateKeyInfo key, IReadOnlyList<X509Certificate> chain, string password, string friendlyName, SecureRandom random)
    {
        var passwordChars = password.ToCharArray();
        var localKeyId = new DerOctetString(DigestUtilities.CalculateDigest("SHA-1", leaf.GetEncoded()));

        var keySalt = RandomBytes(random, 16);
        var encryptedKey = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
            NistObjectIdentifiers.IdAes256Cbc, PkcsObjectIdentifiers.IdHmacWithSha256,
            passwordChars, keySalt, Iterations, random, key);
        var keyBag = new SafeBag(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag, encryptedKey.ToAsn1Object(), Attributes(localKeyId, friendlyName));

        var certificateBags = new List<SafeBag> { CertificateBag(leaf, Attributes(localKeyId, friendlyName)) };
        certificateBags.AddRange(chain.Select(c => CertificateBag(c, null)));

        var authenticatedSafe = new AuthenticatedSafe([Data(keyBag), Data([.. certificateBags])]).GetEncoded(Asn1Encodable.Der);

        var macSalt = RandomBytes(random, 32);
        var generator = new Pkcs12ParametersGenerator(new Sha256Digest());
        generator.Init(PbeParametersGenerator.Pkcs12PasswordToBytes(passwordChars), macSalt, Iterations);
        var hmac = new HMac(new Sha256Digest());
        hmac.Init(generator.GenerateDerivedMacParameters(256));
        hmac.BlockUpdate(authenticatedSafe, 0, authenticatedSafe.Length);
        var mac = new byte[hmac.GetMacSize()];
        hmac.DoFinal(mac, 0);

        var macData = new MacData(new DigestInfo(new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance), mac), macSalt, Iterations);
        return new Pfx(new ContentInfo(PkcsObjectIdentifiers.Data, new DerOctetString(authenticatedSafe)), macData).GetEncoded(Asn1Encodable.Der);
    }

    private static SafeBag CertificateBag(X509Certificate certificate, Asn1Set? attributes) =>
        new(PkcsObjectIdentifiers.CertBag,
            new CertBag(PkcsObjectIdentifiers.X509Certificate, new DerOctetString(certificate.GetEncoded())).ToAsn1Object(),
            attributes!);

    private static ContentInfo Data(params SafeBag[] bags) =>
        new(PkcsObjectIdentifiers.Data, new DerOctetString(new DerSequence(bags).GetEncoded(Asn1Encodable.Der)));

    private static DerSet Attributes(Asn1OctetString localKeyId, string friendlyName) => new(
        new DerSequence(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID, new DerSet(localKeyId)),
        new DerSequence(PkcsObjectIdentifiers.Pkcs9AtFriendlyName, new DerSet(new DerBmpString(friendlyName))));

    private static byte[] RandomBytes(SecureRandom random, int length)
    {
        var bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
