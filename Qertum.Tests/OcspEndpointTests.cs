using System.Net;
using System.Net.Http.Headers;
using Qertum.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>
/// HTTP-level tests for the OCSP responder. These run against a real CertificateGenerator with real
/// CA files, because the point of the endpoint is the signed DER it produces.
/// </summary>
public sealed class OcspEndpointTests : IDisposable
{
    private static readonly AlgorithmIdentifier Sha1 =
        new(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, Org.BouncyCastle.Asn1.DerNull.Instance);

    private readonly string _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
    private readonly CertificateGenerator _generator;
    private readonly X509Certificate _caCertificate;

    public OcspEndpointTests()
    {
        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "OCSP Endpoint Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });

        _caCertificate = new X509CertificateParser().ReadCertificate(
            System.Text.Encoding.UTF8.GetBytes(_generator.GetCaCertificatePem()));
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task Post_RevokedSerial_IsReportedRevokedWithoutAuthentication()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var issued = await SeedCertificateAsync(factory, "revoked-endpoint.contoso.local", revoked: true, ct);

        // No Authorization header: revocation status has to be readable by relying parties, the same
        // reason /crl is public.
        var response = await factory.CreateClient().PostAsync("/ocsp", DerContent(issued), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/ocsp-response", response.Content.Headers.ContentType?.MediaType);
        Assert.IsType<RevokedStatus>(await SingleStatusAsync(response, ct));
    }

    [Fact]
    public async Task RefusedDeletionOfRevokedRequestPreservesCrlAndOcspStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var serial = await SeedCertificateAsync(factory, "delete-revoked-endpoint.contoso.local", revoked: true, ct);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var request = await db.CertificateRequests.SingleAsync(candidate => candidate.SerialNumber == serial, ct);
            var service = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => service.DeleteAsync(request.Id, "test", ct));

            var revoked = await service.GetAllRevokedForCrlAsync(ct);
            var crl = new X509CrlParser().ReadCrl(_generator.GenerateCrl(revoked, new CaSettings { PqcStage = PqcStage.Off }));
            Assert.NotNull(crl.GetRevokedCertificate(new Org.BouncyCastle.Math.BigInteger(serial, 16)));
        }

        var response = await factory.CreateClient().PostAsync("/ocsp", DerContent(serial), ct);
        Assert.IsType<RevokedStatus>(await SingleStatusAsync(response, ct));
    }

    [Fact]
    public async Task Get_IssuedSerial_IsReportedGood()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var issued = await SeedCertificateAsync(factory, "good-endpoint.contoso.local", revoked: false, ct);

        var encoded = Uri.EscapeDataString(Convert.ToBase64String(BuildRequest(issued)));
        var response = await factory.CreateClient().GetAsync($"/ocsp/{encoded}", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Null(await SingleStatusAsync(response, ct));
    }

    [Fact]
    public async Task Post_SerialThisCaNeverIssued_IsUnknown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var request = BuildRequest("0123456789ABCDEF");
        var response = await factory.CreateClient().PostAsync("/ocsp", new ByteArrayContent(request)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/ocsp-request") }
        }, ct);

        Assert.IsType<UnknownStatus>(await SingleStatusAsync(response, ct));
    }

    [Fact]
    public async Task Post_GarbageBody_ReturnsMalformedRequestStatus()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().PostAsync("/ocsp",
            new ByteArrayContent([1, 2, 3, 4]) { Headers = { ContentType = new MediaTypeHeaderValue("application/ocsp-request") } }, ct);

        // RFC 6960 §2.3: a malformed request is answered with an OCSP response carrying that status,
        // not with a transport-level error.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var parsed = new OcspResp(await response.Content.ReadAsByteArrayAsync(ct));
        Assert.Equal(OcspRespStatus.MalformedRequest, parsed.Status);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private WebApplicationFactory<ApiServiceProgram> CreateFactory()
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                database.ReplaceDbContext(services);

                services.AddSingleton<ICertificateGenerator>(_generator);
            });
        });
    }

    private static async Task EnsureDbAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
    }

    private async Task<string> SeedCertificateAsync(
        WebApplicationFactory<ApiServiceProgram> factory, string commonName, bool revoked, CancellationToken ct)
    {
        await EnsureDbAsync(factory, ct);

        var issued = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = commonName, Type = "WebServer" },
            new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = commonName,
            RequestedBy = "test@contoso.local",
            Type = "WebServer",
            Status = revoked ? CertificateRequestStatus.Revoked : CertificateRequestStatus.Issued,
            SerialNumber = issued.SerialNumber,
            CertificatePem = issued.CertificatePem,
            RevokedAtUtc = revoked ? DateTime.UtcNow.AddHours(-1) : null,
            RevocationReason = revoked ? "superseded" : null
        });
        await db.SaveChangesAsync(ct);

        return issued.SerialNumber;
    }

    private byte[] BuildRequest(string serialHex)
    {
        var generator = new OcspReqGenerator();
        generator.AddRequest(new CertificateID(
            Sha1, _caCertificate, new Org.BouncyCastle.Math.BigInteger(serialHex, 16)));
        return generator.Generate().GetEncoded();
    }

    private ByteArrayContent DerContent(string serialHex) =>
        new(BuildRequest(serialHex))
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/ocsp-request") }
        };

    private async Task<object?> SingleStatusAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var parsed = new OcspResp(await response.Content.ReadAsByteArrayAsync(ct));
        Assert.Equal(OcspRespStatus.Successful, parsed.Status);

        var basic = (BasicOcspResp)parsed.GetResponseObject();
        Assert.True(basic.Verify(_caCertificate.GetPublicKey()), "OCSP response is not signed by the CA.");
        return Assert.Single(basic.Responses).GetCertStatus();
    }
}
