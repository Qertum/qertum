using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Qertum.Services.Crypto.Composite;

namespace Qertum.Tests.Crypto;

/// <summary>
/// The registry is the single source for every composite combination, so it is pinned row by row
/// against draft -19 §6: name, OID, label, ML-DSA level, traditional scheme, digests. A typo here
/// would produce signatures nothing else can verify.
/// </summary>
public sealed class CompositeAlgorithmsTests
{
    private sealed record DraftRow(
        string Name, string Oid, string Label, int MlDsaLevel, CompositeTraditional Traditional,
        int RsaBits, string? Curve, string? TraditionalDigest, CompositePreHash PreHash);

    // Copied from draft -19 §6, one row per algorithm.
    private static readonly DraftRow[] Rows =
    [
        new("MLDSA44-RSA2048-PSS-SHA256", "1.3.6.1.5.5.7.6.37", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", 44, CompositeTraditional.RsaPss, 2048, null, "SHA-256", CompositePreHash.Sha256),
        new("MLDSA44-RSA2048-PKCS15-SHA256", "1.3.6.1.5.5.7.6.38", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", 44, CompositeTraditional.RsaPkcs15, 2048, null, "SHA-256", CompositePreHash.Sha256),
        new("MLDSA44-Ed25519-SHA512", "1.3.6.1.5.5.7.6.39", "COMPSIG-MLDSA44-Ed25519-SHA512", 44, CompositeTraditional.Ed25519, 0, null, null, CompositePreHash.Sha512),
        new("MLDSA44-ECDSA-P256-SHA256", "1.3.6.1.5.5.7.6.40", "COMPSIG-MLDSA44-ECDSA-P256-SHA256", 44, CompositeTraditional.Ecdsa, 0, "secp256r1", "SHA-256", CompositePreHash.Sha256),
        new("MLDSA65-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.41", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", 65, CompositeTraditional.RsaPss, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-RSA3072-PKCS15-SHA512", "1.3.6.1.5.5.7.6.42", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", 65, CompositeTraditional.RsaPkcs15, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.43", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", 65, CompositeTraditional.RsaPss, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-RSA4096-PKCS15-SHA512", "1.3.6.1.5.5.7.6.44", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", 65, CompositeTraditional.RsaPkcs15, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-P256-SHA512", "1.3.6.1.5.5.7.6.45", "COMPSIG-MLDSA65-ECDSA-P256-SHA512", 65, CompositeTraditional.Ecdsa, 0, "secp256r1", "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.46", "COMPSIG-MLDSA65-ECDSA-P384-SHA512", 65, CompositeTraditional.Ecdsa, 0, "secp384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA65-ECDSA-brainpoolP256r1-SHA512", "1.3.6.1.5.5.7.6.47", "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", 65, CompositeTraditional.Ecdsa, 0, "brainpoolP256r1", "SHA-256", CompositePreHash.Sha512),
        new("MLDSA65-Ed25519-SHA512", "1.3.6.1.5.5.7.6.48", "COMPSIG-MLDSA65-Ed25519-SHA512", 65, CompositeTraditional.Ed25519, 0, null, null, CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.49", "COMPSIG-MLDSA87-ECDSA-P384-SHA512", 87, CompositeTraditional.Ecdsa, 0, "secp384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-brainpoolP384r1-SHA512", "1.3.6.1.5.5.7.6.50", "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", 87, CompositeTraditional.Ecdsa, 0, "brainpoolP384r1", "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-Ed448-SHAKE256", "1.3.6.1.5.5.7.6.51", "COMPSIG-MLDSA87-Ed448-SHAKE256", 87, CompositeTraditional.Ed448, 0, null, null, CompositePreHash.Shake256With64ByteOutput),
        new("MLDSA87-RSA3072-PSS-SHA512", "1.3.6.1.5.5.7.6.52", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", 87, CompositeTraditional.RsaPss, 3072, null, "SHA-256", CompositePreHash.Sha512),
        new("MLDSA87-RSA4096-PSS-SHA512", "1.3.6.1.5.5.7.6.53", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", 87, CompositeTraditional.RsaPss, 4096, null, "SHA-384", CompositePreHash.Sha512),
        new("MLDSA87-ECDSA-P521-SHA512", "1.3.6.1.5.5.7.6.54", "COMPSIG-MLDSA87-ECDSA-P521-SHA512", 87, CompositeTraditional.Ecdsa, 0, "secp521r1", "SHA-512", CompositePreHash.Sha512),
    ];

    public static TheoryData<string> DraftNames => [.. Rows.Select(r => r.Name)];

    [Theory]
    [MemberData(nameof(DraftNames))]
    public void EveryRowMatchesTheDraft(string name)
    {
        var row = Rows.Single(r => r.Name == name);
        var algorithm = CompositeAlgorithms.FindByName(name);

        Assert.NotNull(algorithm);
        Assert.Equal(row.Oid, algorithm.Oid.Id);
        Assert.Equal(row.Label, algorithm.Label);
        Assert.Equal(MlDsa(row.MlDsaLevel), algorithm.MlDsa);
        Assert.Equal(row.Traditional, algorithm.Traditional);
        Assert.Equal(row.RsaBits, algorithm.RsaKeyBits);
        Assert.Equal(row.Curve, algorithm.CurveName);
        Assert.Equal(row.TraditionalDigest, algorithm.TraditionalDigest);
        Assert.Equal(row.PreHash, algorithm.PreHash);
        Assert.Same(algorithm, CompositeAlgorithms.FindByOid(new DerObjectIdentifier(row.Oid)));
    }

    [Fact]
    public void RegistryHoldsExactlyTheEighteenDraftAlgorithms()
    {
        var expected = Rows.Select(r => r.Name).Order(StringComparer.Ordinal);

        Assert.Equal(expected, CompositeAlgorithms.All.Select(a => a.Name).Order(StringComparer.Ordinal));
        Assert.Equal(18, CompositeAlgorithms.All.Select(a => a.Oid.Id).Distinct().Count());
    }

    [Fact]
    public void NoAlgorithmUsesTheOldEntrustArc()
    {
        // BouncyCastle also ships BCObjectIdentifiers.mldsa65_p256 and friends under
        // 2.16.840.1.114027.80.8.1 — pre-IANA draft OIDs nothing current recognises.
        Assert.All(CompositeAlgorithms.All, a => Assert.StartsWith("1.3.6.1.5.5.7.6.", a.Oid.Id, StringComparison.Ordinal));
    }

    [Fact]
    public void EveryAlgorithmHasAPublishedTestVector()
    {
        var compositeVectors = CompositeTestVectors.ByTcId.Keys.Where(id => id.StartsWith("id-MLDSA", StringComparison.Ordinal));

        Assert.Equal(
            CompositeAlgorithms.All.Select(a => "id-" + a.Name).Order(StringComparer.Ordinal),
            compositeVectors.Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("MLDSA44-ECDSA-P256-SHA256", 1312, 2420)]
    [InlineData("MLDSA65-ECDSA-P256-SHA512", 1952, 3309)]
    [InlineData("MLDSA87-ECDSA-P384-SHA512", 2592, 4627)]
    public void MlDsaSplitLengthsFollowTheParameterSet(string name, int publicKeyLength, int signatureLength)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!;

        Assert.Equal(publicKeyLength, algorithm.MlDsaPublicKeyLength);
        Assert.Equal(signatureLength, algorithm.MlDsaSignatureLength);
    }

    [Fact]
    public void UnknownOidIsNotComposite() =>
        Assert.Null(CompositeAlgorithms.FindByOid(new DerObjectIdentifier("1.2.840.113549.1.1.11")));

    private static MLDsaParameters MlDsa(int level) => level switch
    {
        44 => MLDsaParameters.ml_dsa_44,
        65 => MLDsaParameters.ml_dsa_65,
        87 => MLDsaParameters.ml_dsa_87,
        _ => throw new ArgumentOutOfRangeException(nameof(level))
    };
}
