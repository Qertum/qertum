using System.Security.Cryptography;
using System.Text.Json;
using Qertum.Services.Acme;

namespace Qertum.Tests;

/// <summary>
/// An ACME account key signs every request of its account (orders, finalize, revoke-cert). It was imported with no
/// strength check, so a 512-bit RSA account key, which can be factored, was accepted; CSR keys already had to be
/// 2048 to 16384 bits with an odd exponent of at least 65537. Account keys now meet the same rule.
/// </summary>
public sealed class AcmeAccountKeyStrengthTests
{
    private static string Jwk(byte[] modulus, byte[] exponent) => JsonSerializer.Serialize(new
    {
        kty = "RSA", n = JwkConverter.Base64UrlEncode(modulus), e = JwkConverter.Base64UrlEncode(exponent)
    });

    private static string Jwk(int bits)
    {
        using var rsa = RSA.Create(bits);
        var p = rsa.ExportParameters(false);
        return Jwk(p.Modulus!, p.Exponent!);
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(1536)]
    public void AWeakRsaAccountKey_IsRefusedAsBadPublicKey(int bits)
    {
        var ex = Assert.Throws<AcmeException>(() => JwkConverter.ImportPublicKey(Jwk(bits)));
        Assert.Equal("badPublicKey", ex.ErrorType);
        Assert.Contains("2048", ex.Message);
    }

    [Fact]
    public void AnRsaAccountKeyWithASmallExponent_IsRefused()
    {
        using var rsa = RSA.Create(2048);
        var p = rsa.ExportParameters(false);

        var ex = Assert.Throws<AcmeException>(() => JwkConverter.ImportPublicKey(Jwk(p.Modulus!, [3])));
        Assert.Equal("badPublicKey", ex.ErrorType);
    }

    [Fact]
    public void A2048BitRsaAccountKey_IsAccepted()
    {
        using var key = JwkConverter.ImportPublicKey(Jwk(2048));
        Assert.IsAssignableFrom<RSA>(key);
    }
}
