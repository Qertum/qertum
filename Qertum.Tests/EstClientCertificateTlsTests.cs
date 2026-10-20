using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Xunit;

namespace Qertum.Tests;

public sealed class EstClientCertificateTlsTests
{
    private static HttpsConnectionAdapterOptions Configured()
    {
        var https = new HttpsConnectionAdapterOptions();
        EstClientCertificateTls.Configure(https);
        return https;
    }

    [Fact]
    public void ClientCertificate_IsRequested_NeverRequired()
    {
        // /simpleenroll and the public routes present no certificate; requiring one would break them.
        Assert.Equal(ClientCertificateMode.AllowCertificate, Configured().ClientCertificateMode);
    }

    [Fact]
    public void ClientCertificate_IsPassedOnWithoutPlatformChainValidation()
    {
        // A PQC, composite or private-root chain the platform cannot build must still reach /simplereenroll,
        // which validates the chain against Qertum's own issuers.
        var validation = Configured().ClientCertificateValidation;

        Assert.NotNull(validation);
        using var key = System.Security.Cryptography.ECDsa.Create();
        var request = new CertificateRequest("CN=untrusted", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.True(validation!(certificate, null, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors));
    }
}
