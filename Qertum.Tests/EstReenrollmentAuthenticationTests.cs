using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Qertum.Services;
using Qertum.Services.Issuers;
using Qertum.Services.Est;
using Qertum.Tests.Issuers;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

public sealed class EstReenrollmentAuthenticationTests
{
    [Theory]
    [InlineData(null, true, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized)]
    [InlineData("ordinary-user", true, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized)]
    [InlineData("est:credential", false, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized)]
    [InlineData("est:credential", true, CertificateRequestStatus.PendingRevocation, HttpStatusCode.Unauthorized)]
    [InlineData("est:credential", true, CertificateRequestStatus.Issued, HttpStatusCode.Accepted)]
    [InlineData("est-cert:012345", true, CertificateRequestStatus.Issued, HttpStatusCode.Accepted)]
    [InlineData("est:credential", true, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized, "not-a-certificate")]
    [InlineData("est:credential", true, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized, "")]
    [InlineData("est:credential", true, CertificateRequestStatus.Issued, HttpStatusCode.Unauthorized, "mismatch")]
    public async Task Reenrollment_RequiresAnIssuedEstCertificateWithClientAuthentication(
        string? enrollmentIdentity, bool clientAuth, CertificateRequestStatus status, HttpStatusCode expected, string? storedCertificate = null)
    {
        var ct = TestContext.Current.CancellationToken;
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        using var parent = new EstTestFactory();
        using var factory = parent.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<ICertificateGenerator>(kit.Legacy);
            services.AddSingleton<IIssuerRegistry>(kit.NewRegistry());
        }));
        using var client = factory.CreateClient();
        const string name = "reenroll-auth.example.test";
        var issued = kit.Legacy.GenerateCertificate(new CertificateRequest { CommonName = name },
            new CaSettings { PqcStage = PqcStage.Off }, new CertificateTemplate
            {
                TypeKey = "Device", Name = "Device", KeyUsagesJson = "[\"DigitalSignature\"]",
                ExtendedKeyUsagesJson = clientAuth ? "[\"1.3.6.1.5.5.7.3.2\"]" : "[\"1.3.6.1.5.5.7.3.1\"]"
            });
        using var certificate = X509Certificate2.CreateFromPem(issued.CertificatePem);
        var holder = factory.Services.GetRequiredService<TestClientCertificateHolder>();
        holder.Certificate = certificate;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            if (enrollmentIdentity is not null)
            {
                db.CertificateRequests.Add(new CertificateRequest
                {
                    CommonName = name, RequestedBy = enrollmentIdentity, RequestedBySubject = enrollmentIdentity,
                    Status = status, SerialNumber = issued.SerialNumber,
                    CertificatePem = storedCertificate == "mismatch"
                        ? kit.Legacy.GenerateCertificate(new CertificateRequest { CommonName = name }, new CaSettings { PqcStage = PqcStage.Off }).CertificatePem
                        : storedCertificate ?? issued.CertificatePem,
                    CsrPem = "original-est-csr"
                });
                await db.SaveChangesAsync(ct);
            }
        }
        var csr = TestCsrBuilder.BuildBase64Url(name, []);
        using var body = new StringContent(csr, Encoding.ASCII, "application/pkcs10");

        using var response = await client.PostAsync("/.well-known/est/simplereenroll", body, ct);

        Assert.Equal(expected, response.StatusCode);
        using var verifyScope = factory.Services.CreateScope();
        var verifyDb = verifyScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(expected == HttpStatusCode.Accepted ? 1 : 0,
            await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.CountAsync(
                verifyDb.CertificateRequests.Where(request => request.CsrPem == csr), ct));
    }
}
