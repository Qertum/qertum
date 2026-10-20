using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Acme;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

/// <summary>RFC 9773: the certificate identifier, the suggested window and the <c>renewal-info</c> endpoint.</summary>
public sealed class AcmeRenewalInfoTests : IDisposable
{
    private static readonly DateTime Now = new(2026, 10, 17, 12, 0, 0, DateTimeKind.Utc);

    private readonly string _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
    private readonly CertificateGenerator _generator;

    public AcmeRenewalInfoTests()
    {
        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(), new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);
        _generator.GenerateCa(new GenerateCaRequest { CommonName = "ARI Root", KeyAlgorithm = CertificateKeyAlgorithm.Rsa, ValidityDays = 365 });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    private string IssueLeafPem() =>
        _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "ari.contoso.local", Type = "WebServer", PropertiesJson = "{}" },
            new CaSettings { PqcStage = PqcStage.Off }).CertificatePem;

    private static BcCertificate Parse(string pem) => Qertum.Services.Crypto.QertumKeyCodec.ReadCertificatePem(pem)!;

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // ── identifier ──────────────────────────────────────────────────────────────

    [Fact]
    public void CertId_RoundTripsAnIssuedCertificate()
    {
        var cert = Parse(IssueLeafPem());

        var id = AcmeRenewalInfo.CertIdFor(cert);

        Assert.NotNull(id);
        Assert.True(AcmeRenewalInfo.TryParseCertId(id, out var keyId, out var serialHex));
        Assert.Equal(AcmeRenewalInfo.AuthorityKeyIdOf(cert), keyId);
        Assert.Equal(cert.SerialNumber.ToString(16).ToUpperInvariant(), serialHex);
    }

    [Fact]
    public void CertId_KeepsTheLeadingZeroOctetOfAHighBitSerial()
    {
        // DER INTEGER 0x00 0x80: the serial is 128, not negative.
        Assert.True(AcmeRenewalInfo.TryParseCertId($"{Encode([1, 2])}.{Encode([0x00, 0x80])}", out _, out var serialHex));
        Assert.Equal("80", serialHex);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("onlyonepart")]
    [InlineData("AQI.AQ.AQ")]            // three parts
    [InlineData("AQI=.AQ")]              // padded
    [InlineData("AQI.AQ+")]              // not base64url
    [InlineData(".AQ")]                  // no key id
    [InlineData("AQI.")]                 // no serial
    [InlineData("AQI.gA")]               // 0x80: negative as a DER INTEGER
    public void CertId_RejectsMalformedIdentifiers(string? id) =>
        Assert.False(AcmeRenewalInfo.TryParseCertId(id, out _, out _));

    [Fact]
    public void CertId_RejectsASerialLongerThan20Octets() =>
        Assert.False(AcmeRenewalInfo.TryParseCertId($"AQI.{Encode(new byte[21].Select(_ => (byte)1).ToArray())}", out _, out _));

    // ── window ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Window_StartsTheConfiguredDaysBeforeExpiryAndLastsADay()
    {
        var (start, end) = AcmeRenewalInfo.SuggestedWindow(Now.AddDays(-80), Now.AddDays(100), false, 30, Now);

        Assert.Equal(Now.AddDays(70), start);
        Assert.Equal(Now.AddDays(71), end);
    }

    [Fact]
    public void Window_NeverStartsBeforeHalfTheLifetime()
    {
        // A 10-day certificate with a 30-day threshold must not be told to renew the moment it is issued.
        var (start, _) = AcmeRenewalInfo.SuggestedWindow(Now, Now.AddDays(10), false, 30, Now);

        Assert.Equal(Now.AddDays(5), start);
    }

    [Fact]
    public void Window_EndsAtExpiryAtTheLatest()
    {
        var validTo = Now.AddDays(100);
        var (start, end) = AcmeRenewalInfo.SuggestedWindow(Now.AddDays(-80), validTo, false, 0, Now);

        Assert.Equal(validTo, start);
        Assert.Equal(validTo, end);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Window_IsAlreadyOverWhenRenewNowOrExpired(bool renewNow)
    {
        var validTo = renewNow ? Now.AddDays(100) : Now.AddDays(-1);
        var (start, end) = AcmeRenewalInfo.SuggestedWindow(Now.AddDays(-80), validTo, renewNow, 30, Now);

        Assert.True(start < end);
        Assert.True(end <= Now);
    }

    // ── endpoint ────────────────────────────────────────────────────────────────

    private WebApplicationFactory<AcmeServiceProgram> CreateFactory()
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        return new WebApplicationFactory<AcmeServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.UseSetting("Acme:BaseUrl", "http://localhost");
            builder.ConfigureTestServices(services =>
            {
                database.ReplaceDbContext(services);
                services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
                services.AddSingleton<ICertificateGenerator>(_generator);
            });
        });
    }

    private static async Task<string> SeedAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, string pem, CertificateRequestStatus status,
        DateTime validFrom, DateTime validTo, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var cert = Parse(pem);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "ari.contoso.local", RequestedBy = "test", Status = status, CertificatePem = pem,
            SerialNumber = cert.SerialNumber.ToString(16).ToUpperInvariant(), ValidFrom = validFrom, ValidTo = validTo
        });
        await db.SaveChangesAsync(ct);
        return AcmeRenewalInfo.CertIdFor(cert)!;
    }

    private static async Task<(DateTime Start, DateTime End)> WindowOf(HttpResponseMessage response, CancellationToken ct)
    {
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        var window = json.GetProperty("suggestedWindow");
        return (window.GetProperty("start").GetDateTime().ToUniversalTime(), window.GetProperty("end").GetDateTime().ToUniversalTime());
    }

    [Fact]
    public async Task Directory_AdvertisesRenewalInfo()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        var json = await factory.CreateClient().GetFromJsonAsync<JsonElement>("/acme/directory", ct);

        Assert.Equal("http://localhost/acme/renewal-info", json.GetProperty("renewalInfo").GetString());
    }

    [Fact]
    public async Task RenewalInfo_AnIssuedCertificateGetsItsWindowAndRetryAfter()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var now = DateTime.UtcNow;
        var id = await SeedAsync(factory, IssueLeafPem(), CertificateRequestStatus.Issued, now.AddDays(-80), now.AddDays(100), ct);

        var response = await factory.CreateClient().GetAsync($"/acme/renewal-info/{id}", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("21600", Assert.Single(response.Headers.GetValues("Retry-After")));
        var (start, end) = await WindowOf(response, ct);
        Assert.InRange((start - now.AddDays(70)).TotalSeconds, -5, 5);
        Assert.Equal(TimeSpan.FromDays(1), end - start);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Revoked)]
    [InlineData(CertificateRequestStatus.PendingRevocation)]
    public async Task RenewalInfo_ARevokedCertificateIsToBeRenewedNow(CertificateRequestStatus status)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var now = DateTime.UtcNow;
        var id = await SeedAsync(factory, IssueLeafPem(), status, now.AddDays(-80), now.AddDays(100), ct);

        var response = await factory.CreateClient().GetAsync($"/acme/renewal-info/{id}", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var (_, end) = await WindowOf(response, ct);
        Assert.True(end <= DateTime.UtcNow);
    }

    [Fact]
    public async Task RenewalInfo_AnUnissuedRequestAndAnUnknownSerialAreNotFound()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var now = DateTime.UtcNow;
        var pem = IssueLeafPem();
        var pending = await SeedAsync(factory, pem, CertificateRequestStatus.Approved, now.AddDays(-1), now.AddDays(89), ct);
        var unknown = AcmeRenewalInfo.CertIdFor(Parse(IssueLeafPem()))!;
        var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/acme/renewal-info/{pending}", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/acme/renewal-info/{unknown}", ct)).StatusCode);
    }

    [Fact]
    public async Task RenewalInfo_ASerialWithAnotherAuthorityKeyIdIsNotFound()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        var now = DateTime.UtcNow;
        var id = await SeedAsync(factory, IssueLeafPem(), CertificateRequestStatus.Issued, now.AddDays(-1), now.AddDays(89), ct);
        var serialPart = id.Split('.')[1];

        var response = await factory.CreateClient().GetAsync($"/acme/renewal-info/{Encode([9, 9, 9, 9])}.{serialPart}", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task RenewalInfo_AMalformedIdentifierIsABadRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        var response = await factory.CreateClient().GetAsync("/acme/renewal-info/not-an-identifier", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
