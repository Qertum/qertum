using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qertum.Services.Webhooks;

namespace Qertum.Tests.Webhooks;

public sealed class PublicKeyThumbprintTests
{
    private static string SelfSignedPem(out ECDsa key)
    {
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=thumbprint.test", key, HashAlgorithmName.SHA256);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return cert.ExportCertificatePem();
    }

    [Fact]
    public void IsTheLowercaseHexSha256OfTheSubjectPublicKeyInfo()
    {
        var pem = SelfSignedPem(out var key);
        using (key)
        {
            using var cert = X509Certificate2.CreateFromPem(pem);
            var expected = Convert.ToHexString(SHA256.HashData(cert.PublicKey.ExportSubjectPublicKeyInfo()))
                .ToLowerInvariant();

            Assert.Equal(expected, PublicKeyThumbprint.FromCertificatePem(pem));
        }
    }

    [Fact]
    public void IsStableAcrossRepeatedCalls()
    {
        var pem = SelfSignedPem(out var key);
        using (key)
            Assert.Equal(PublicKeyThumbprint.FromCertificatePem(pem), PublicKeyThumbprint.FromCertificatePem(pem));
    }

    [Fact]
    public void DiffersBetweenTwoKeys()
    {
        var first = SelfSignedPem(out var keyA);
        var second = SelfSignedPem(out var keyB);
        using (keyA)
        using (keyB)
            Assert.NotEqual(PublicKeyThumbprint.FromCertificatePem(first), PublicKeyThumbprint.FromCertificatePem(second));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----")]
    public void ReturnsNullRatherThanThrowing(string? pem)
        => Assert.Null(PublicKeyThumbprint.FromCertificatePem(pem));
}
