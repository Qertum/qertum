using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Qertum.Services.Crypto.Composite;

/// <summary>
/// The traditional component of a composite key: generation, the §4 serializations, and the
/// signer. Kept apart from the composite types so the per-scheme detail sits in one switch per
/// operation.
/// </summary>
internal static class CompositeTraditionalKeys
{
    private static readonly BigInteger RsaPublicExponent = BigInteger.ValueOf(65537);

    public static AsymmetricCipherKeyPair Generate(CompositeAlgorithm algorithm, SecureRandom random)
    {
        switch (algorithm.Traditional)
        {
            case CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15:
                var rsa = new RsaKeyPairGenerator();
                rsa.Init(new RsaKeyGenerationParameters(RsaPublicExponent, random, algorithm.RsaKeyBits, 100));
                return rsa.GenerateKeyPair();
            case CompositeTraditional.Ecdsa:
                var ec = new ECKeyPairGenerator();
                ec.Init(new ECKeyGenerationParameters(CurveOid(algorithm), random));
                return ec.GenerateKeyPair();
            case CompositeTraditional.Ed25519:
                var ed25519 = new Ed25519KeyPairGenerator();
                ed25519.Init(new Ed25519KeyGenerationParameters(random));
                return ed25519.GenerateKeyPair();
            case CompositeTraditional.Ed448:
                var ed448 = new Ed448KeyPairGenerator();
                ed448.Init(new Ed448KeyGenerationParameters(random));
                return ed448.GenerateKeyPair();
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm.Traditional, null);
        }
    }

    /// <summary>§4.1: RSAPublicKey DER, an uncompressed X9.62 point, or the raw RFC 8032 key.</summary>
    public static byte[] EncodePublic(CompositeAlgorithm algorithm, AsymmetricKeyParameter key) => (algorithm.Traditional, key) switch
    {
        (CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15, RsaKeyParameters rsa) =>
            new RsaPublicKeyStructure(rsa.Modulus, rsa.Exponent).GetEncoded(Asn1Encodable.Der),
        (CompositeTraditional.Ecdsa, ECPublicKeyParameters ec) => ec.Q.GetEncoded(compressed: false),
        (CompositeTraditional.Ed25519, Ed25519PublicKeyParameters ed) => ed.GetEncoded(),
        (CompositeTraditional.Ed448, Ed448PublicKeyParameters ed) => ed.GetEncoded(),
        _ => throw new ArgumentException($"A {key.GetType().Name} is not the traditional public key of {algorithm.Name}.", nameof(key))
    };

    public static AsymmetricKeyParameter DecodePublic(CompositeAlgorithm algorithm, byte[] encoded)
    {
        switch (algorithm.Traditional)
        {
            case CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15:
                var rsa = RsaPublicKeyStructure.GetInstance(Asn1Object.FromByteArray(encoded));
                RequireRsaSize(algorithm, rsa.Modulus);
                return new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent);
            case CompositeTraditional.Ecdsa:
                var domain = Domain(algorithm);
                // DecodePoint rejects a point that is not on the curve.
                return new ECPublicKeyParameters(domain.Curve.DecodePoint(encoded), domain);
            case CompositeTraditional.Ed25519:
                return new Ed25519PublicKeyParameters(encoded);
            case CompositeTraditional.Ed448:
                return new Ed448PublicKeyParameters(encoded);
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm.Traditional, null);
        }
    }

    /// <summary>
    /// §4.2: RSAPrivateKey v0, ECPrivateKey with the curve OID and no public key, or the raw
    /// RFC 8032 key.
    /// </summary>
    public static byte[] EncodePrivate(CompositeAlgorithm algorithm, AsymmetricKeyParameter key) => (algorithm.Traditional, key) switch
    {
        (CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15, RsaPrivateCrtKeyParameters rsa) =>
            new RsaPrivateKeyStructure(rsa.Modulus, rsa.PublicExponent, rsa.Exponent, rsa.P, rsa.Q, rsa.DP, rsa.DQ, rsa.QInv)
                .GetEncoded(Asn1Encodable.Der),
        (CompositeTraditional.Ecdsa, ECPrivateKeyParameters ec) =>
            new ECPrivateKeyStructure(ec.Parameters.N.BitLength, ec.D, new X962Parameters(CurveOid(algorithm)))
                .GetEncoded(Asn1Encodable.Der),
        (CompositeTraditional.Ed25519, Ed25519PrivateKeyParameters ed) => ed.GetEncoded(),
        (CompositeTraditional.Ed448, Ed448PrivateKeyParameters ed) => ed.GetEncoded(),
        _ => throw new ArgumentException($"A {key.GetType().Name} is not the traditional private key of {algorithm.Name}.", nameof(key))
    };

    public static AsymmetricKeyParameter DecodePrivate(CompositeAlgorithm algorithm, byte[] encoded)
    {
        switch (algorithm.Traditional)
        {
            case CompositeTraditional.RsaPss or CompositeTraditional.RsaPkcs15:
                var rsa = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(encoded));
                RequireRsaSize(algorithm, rsa.Modulus);
                return new RsaPrivateCrtKeyParameters(rsa);
            case CompositeTraditional.Ecdsa:
                var ec = ECPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(encoded));
                if (ec.Parameters is { } parameters
                    && !X962Parameters.GetInstance(parameters).Parameters.Equals(CurveOid(algorithm)))
                    throw new ArgumentException($"The ECDSA private key is not on {algorithm.CurveName}.", nameof(encoded));
                return new ECPrivateKeyParameters(ec.GetKey(), Domain(algorithm));
            case CompositeTraditional.Ed25519:
                return new Ed25519PrivateKeyParameters(encoded);
            case CompositeTraditional.Ed448:
                return new Ed448PrivateKeyParameters(encoded);
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm.Traditional, null);
        }
    }

    public static AsymmetricKeyParameter PublicFromPrivate(AsymmetricKeyParameter privateKey) => privateKey switch
    {
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters(ec.Parameters.G.Multiply(ec.D).Normalize(), ec.Parameters),
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        Ed448PrivateKeyParameters ed => ed.GeneratePublicKey(),
        _ => throw new ArgumentException($"A {privateKey.GetType().Name} is not a composite traditional key.", nameof(privateKey))
    };

    /// <summary>The traditional signer, over M' as-is: EdDSA is pure (no ctx, §3.2), RSA/ECDSA hash M' themselves.</summary>
    public static ISigner CreateSigner(CompositeAlgorithm algorithm) => algorithm.Traditional switch
    {
        CompositeTraditional.RsaPss => new PssSigner(new RsaBlindedEngine(),
            DigestUtilities.GetDigest(algorithm.TraditionalDigest), DigestUtilities.GetDigest(algorithm.TraditionalDigest),
            algorithm.PssSaltLength),
        CompositeTraditional.RsaPkcs15 => new RsaDigestSigner(DigestUtilities.GetDigest(algorithm.TraditionalDigest)),
        // DsaDigestSigner's default encoding is the DER Ecdsa-Sig-Value §4 requires.
        CompositeTraditional.Ecdsa => new DsaDigestSigner(new ECDsaSigner(), DigestUtilities.GetDigest(algorithm.TraditionalDigest)),
        CompositeTraditional.Ed25519 => new Ed25519Signer(),
        CompositeTraditional.Ed448 => new Ed448Signer([]),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm.Traditional, null)
    };

    /// <summary>Signing parameters: EdDSA is deterministic and takes no randomness; the others do.</summary>
    public static ICipherParameters SigningParameters(AsymmetricKeyParameter privateKey, SecureRandom random) =>
        privateKey is Ed25519PrivateKeyParameters or Ed448PrivateKeyParameters
            ? privateKey
            : new ParametersWithRandom(privateKey, random);

    private static DerObjectIdentifier CurveOid(CompositeAlgorithm algorithm) =>
        ECNamedCurveTable.GetOid(algorithm.CurveName)
        ?? throw new InvalidOperationException($"BouncyCastle does not know the curve '{algorithm.CurveName}'.");

    private static ECNamedDomainParameters Domain(CompositeAlgorithm algorithm)
    {
        var oid = CurveOid(algorithm);
        return new ECNamedDomainParameters(oid, ECNamedCurveTable.GetByOid(oid));
    }

    private static void RequireRsaSize(CompositeAlgorithm algorithm, BigInteger modulus)
    {
        if (modulus.BitLength != algorithm.RsaKeyBits)
            throw new ArgumentException(
                $"{algorithm.Name} needs an RSA-{algorithm.RsaKeyBits} key; this one is {modulus.BitLength} bits.");
    }
}
