using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Xunit;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

// ReSharper disable AccessToDisposedClosure

namespace Qertum.Tests;

// ── Stubs ─────────────────────────────────────────────────────────────────────

file sealed class EstStubCertGenerator : ICertificateGenerator
{
    private readonly string _caCertPem = ExportPem(TestCertificates.CreateSelfSigned("CN=Est Test CA"));

    public bool IsInitialized => true;
    public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
    public string GetCaCertificatePem() => _caCertPem;
    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => [];
    public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => [];
    public GeneratedCertificate GenerateCa(GenerateCaRequest request) => FakeCert();
    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];
    public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null) => [];

    public void ImportCa(ImportCaRequest request) { }
    public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => FakeCert();
    public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null)
        => new()
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake-est-csr\n-----END CERTIFICATE-----",
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        };

    private static GeneratedCertificate FakeCert() => new()
    {
        CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
        PrivateKeyPem = string.Empty,
        ValidFrom = DateTime.UtcNow,
        ValidTo = DateTime.UtcNow.AddYears(1)
    };

    private static string ExportPem(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
        => cert.ExportCertificatePem();
}

sealed class TestClientCertificateHolder
{
    public X509Certificate2? Certificate { get; set; }
}

file sealed class TestClientCertificateStartupFilter(TestClientCertificateHolder certificates) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            context.Connection.ClientCertificate = certificates.Certificate;
            await nextMiddleware();
        });
        next(app);
    };
}

// ── Fixture ───────────────────────────────────────────────────────────────────

/// <summary>
/// <see cref="WebApplicationFactory{TEntryPoint}"/> fixture for <c>Qertum.EstService</c>, patterned
/// directly on <c>AcmeProtocolTests.cs</c>'s equivalent factory: in-memory SQLite DB created before
/// the host starts, and a stub <see cref="ICertificateGenerator"/> so no CA files are needed on disk.
/// </summary>
public sealed class EstTestFactory : WebApplicationFactory<EstServiceProgram>
{
    private readonly SharedInMemoryDatabase _database = SharedInMemoryDatabase.Create(createSchema: true);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
        // WebApplicationFactory's in-memory TestServer serves over plain HTTP; the requireHttps
        // check in EstEndpointMappings would otherwise reject every enrollment in this fixture.
        builder.UseSetting("Est:RequireHttps", "false");
        builder.UseSetting("Est:RateLimits:PermitLimit", "1000");
        builder.ConfigureTestServices(services =>
        {
            // A connection per context, never one shared object: see SharedInMemoryDatabase.
            _database.ReplaceDbContext(services);

            // Each factory gets its own key ring, same reasoning as AcmeProtocolTests: the connection
            // string is an in-memory SQLite database with no directory, so AddCustomCaServices falls
            // back to a machine-global DataProtection-Keys folder shared by every test class running
            // in parallel — which makes anything encrypted at rest decrypt only by luck.
            services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();

            services.AddSingleton<ICertificateGenerator>(new EstStubCertGenerator());
            services.AddSingleton<Qertum.Services.Lifecycle.IDiagnosticEventLog>(Diagnostics);
            services.AddSingleton<TestClientCertificateHolder>();
            services.AddSingleton<IStartupFilter, TestClientCertificateStartupFilter>();
        });
    }

    public Lifecycle.RecordingDiagnosticEventLog Diagnostics { get; } = new();

    /// <summary>Seeds an enabled credential and returns its id.</summary>
    public async Task<Guid> SeedCredentialAsync(string username, string password, CancellationToken ct)
    {
        using var scope = Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<Qertum.Services.Est.IEstEnrollmentCredentialService>();
        var created = await service.CreateAsync(username, password, "test-fixture", cancellationToken: ct);
        return created.Credential.Id;
    }

    private bool _credentialSeeded;

    /// <summary>
    /// Seeds one <see cref="Qertum.Services.Est.EstEnrollmentCredential"/> (username <c>test-device</c>,
    /// password <c>test-password</c>) and returns an <see cref="HttpClient"/> with HTTP Basic auth
    /// preset for it. <paramref name="estAutoApprove"/> upserts <see cref="CaSettings"/> beforehand.
    /// </summary>
    public HttpClient CreateAuthenticatedClient(bool estAutoApprove = false)
    {
        using (var scope = Services.CreateScope())
        {
            // IClassFixture shares this factory across every test in the class, so guard against
            // re-seeding the same username on a second CreateAuthenticatedClient call.
            if (!_credentialSeeded)
            {
                var credentials = scope.ServiceProvider.GetRequiredService<Qertum.Services.Est.IEstEnrollmentCredentialService>();
                credentials.CreateAsync("test-device", "test-password", "test-fixture").GetAwaiter().GetResult();
                _credentialSeeded = true;
            }

            var certRequests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
            var settings = certRequests.GetSettingsAsync().GetAwaiter().GetResult();
            settings.EstAutoApprove = estAutoApprove;
            certRequests.SetupOrUpdateSettingsAsync(settings, "test-fixture").GetAwaiter().GetResult();
        }

        var client = CreateClient();
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("test-device:test-password"));
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", basic);
        return client;
    }

    public IDisposable PresentClientCertificate(X509Certificate2 certificate)
    {
        var holder = Services.GetRequiredService<TestClientCertificateHolder>();
        holder.Certificate = certificate;
        return new ClientCertificateReset(holder);
    }

    private sealed class ClientCertificateReset(TestClientCertificateHolder holder) : IDisposable
    {
        public void Dispose() => holder.Certificate = null;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

public class EstProtocolTests : IClassFixture<EstTestFactory>
{
    private readonly EstTestFactory _factory;

    public EstProtocolTests(EstTestFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/simpleenroll", true)]
    [InlineData("/simplereenroll", false)]
    public async Task OversizedEnrollmentBody_ReturnsPayloadTooLarge(string path, bool basicAuth)
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = basicAuth ? _factory.CreateAuthenticatedClient() : _factory.CreateClient();
        var response = await client.PostAsync("/.well-known/est" + path,
            new StringContent(new string('A', 98_305)), ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task OversizedDecodedCsr_ReturnsPayloadTooLarge()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = Convert.ToBase64String(new byte[65_537]);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr), ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task Cacerts_returns_pkcs7_mime_with_no_auth()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/est/cacerts", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pkcs7-mime", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync(ct);
        var certs = Qertum.Services.Est.EstCmsHelper.ParseDegenerateCms(body);
        Assert.Single(certs);
    }

    [Fact]
    public async Task Cacerts_body_is_definite_length_DER()
    {
        // The certs-only response goes through PKCS#7 parsers that only accept definite lengths
        // (go.mozilla.org/pkcs7, used by globalsign/est, fails with "ber2der: Invalid BER format").
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/est/cacerts", ct);

        var bytes = Convert.FromBase64String((await response.Content.ReadAsStringAsync(ct)).Trim());
        var reencoded = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(bytes).GetEncoded(Org.BouncyCastle.Asn1.Asn1Encodable.Der);
        Assert.Equal(reencoded, bytes);
    }

    [Fact]
    public async Task Csrattrs_returns_empty_sequence_with_no_auth()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient();

        var response = await client.GetAsync("/.well-known/est/csrattrs", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Simpleenroll_without_credentials_returns_401_with_basic_challenge()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient();
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "no-creds.example.com", sanDnsNames: []);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains("Basic", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task Enrollments_AreCountedByOperationAndOutcome()
    {
        var ct = TestContext.Current.CancellationToken;
        using var recorder = new MetricsRecorder(
            _factory.Services.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>(), ProtocolMetrics.MeterName);
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "metrics-device.example.com", sanDnsNames: []);
        StringContent Body() => new(csr, System.Text.Encoding.ASCII, "application/pkcs10");

        using (var anonymous = _factory.CreateClient())
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/.well-known/est/simpleenroll", Body(), ct)).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/.well-known/est/simplereenroll", Body(), ct)).StatusCode);
        }

        using (var authenticated = _factory.CreateAuthenticatedClient())
        {
            Assert.Equal(HttpStatusCode.Accepted, (await authenticated.PostAsync("/.well-known/est/simpleenroll", Body(), ct)).StatusCode);
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge,
                (await authenticated.PostAsync("/.well-known/est/simpleenroll", new StringContent(new string('A', 98_305)), ct)).StatusCode);
        }

        Assert.Equal(1, recorder.Sum("ca.est.enrollments", ("operation", "enroll"), ("outcome", "unauthorized")));
        Assert.Equal(1, recorder.Sum("ca.est.enrollments", ("operation", "reenroll"), ("outcome", "unauthorized")));
        Assert.Equal(1, recorder.Sum("ca.est.enrollments", ("operation", "enroll"), ("outcome", "pending")));
        Assert.Equal(1, recorder.Sum("ca.est.enrollments", ("operation", "enroll"), ("outcome", "refused")));
    }

    [Fact]
    public async Task Simpleenroll_with_valid_credentials_and_no_auto_approve_returns_202()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient(); // configures HTTP Basic with a seeded credential
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "device1.example.com", sanDnsNames: []);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter);
    }

    [Fact]
    public async Task Simpleenroll_retry_after_still_pending_returns_202_again()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "device2.example.com", sanDnsNames: []);
        var content = () => new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10");

        var first = await client.PostAsync("/.well-known/est/simpleenroll", content(), ct);
        var second = await client.PostAsync("/.well-known/est/simpleenroll", content(), ct);

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        Assert.NotNull(second.Headers.RetryAfter);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CsrPem == csr, ct));
    }

    /// <summary>
    /// Standard base64 of the CSR broken into lines the way RFC 2045 (and so RFC 7030 clients such as
    /// libest and globalsign/est) do, using a width for which the whole text (breaks included, minus the trailing one the server trims) is 2 or 3 characters past a multiple of four:
    /// the case that used to make the server add padding that was already there.
    /// </summary>
    private static string WrappedBase64(string csrBase64Url, string separator)
    {
        var standard = csrBase64Url.Replace('-', '+').Replace('_', '/');
        standard = standard.PadRight(standard.Length + (4 - standard.Length % 4) % 4, '=');
        for (var width = 60; width <= 100; width++)
        {
            var lines = Enumerable.Range(0, (standard.Length + width - 1) / width)
                .Select(i => standard.Substring(i * width, Math.Min(width, standard.Length - i * width))).ToList();
            var wrapped = string.Join(separator, lines) + separator;
            if ((wrapped.Length - separator.Length) % 4 is 2 or 3)
                return wrapped;
        }

        throw new InvalidOperationException("no wrap width found");
    }

    [Theory]
    [InlineData("\r\n")]
    [InlineData("\n")]
    public async Task Simpleenroll_accepts_a_body_wrapped_into_lines(string separator)
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "wrapped-" + separator.Length + ".example.com", sanDnsNames: []);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(WrappedBase64(csr, separator), System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Fact]
    public async Task Simpleenroll_treats_a_retry_with_different_line_wrapping_as_the_same_request()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "rewrapped.example.com", sanDnsNames: []);

        var first = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(WrappedBase64(csr, "\r\n"), System.Text.Encoding.ASCII, "application/pkcs10"), ct);
        var second = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(WrappedBase64(csr, "\n"), System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CommonName == "rewrapped.example.com", ct));
    }

    [Fact]
    public async Task Simpleenroll_with_auto_approve_signals_the_queue()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient(estAutoApprove: true);
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "device3.example.com", sanDnsNames: []);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        // Approved rows go straight to the queue; without a running consumer in this test host
        // the row stays Approved, which the still-pending/202 path also covers.
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Fact]
    public async Task Simpleenroll_with_mldsa_csr_records_mldsa_algorithm_when_pqc_only_is_off()
    {
        // Same defect as the ACME finalize path: an ML-DSA CSR recorded as RSA makes the generator
        // pick RsaAlgorithmStrategy and stamp keyEncipherment onto a signature-only key.
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildMlDsaBase64Url("pqc-device.example.com", []);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = await db.CertificateRequests
            .SingleAsync(r => r.CommonName == "pqc-device.example.com", ct);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65, request.KeyAlgorithm);
    }

    [Fact]
    public async Task Simpleenroll_AtEnforce_ReturnsBadRequestForRsa()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        await SetStageAsync(PqcStage.Enforce, ct);
        try
        {
            var response = await client.PostAsync("/.well-known/est/simpleenroll",
                new StringContent(TestCsrBuilder.BuildBase64Url("enforced.example.com", []),
                    System.Text.Encoding.ASCII, "application/pkcs10"), ct);

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("classical", await response.Content.ReadAsStringAsync(ct));
        }
        finally
        {
            await SetStageAsync(PqcStage.Off, ct);
        }
    }

    [Fact]
    public async Task Simpleenroll_AtWarn_AcceptsRsa()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        await SetStageAsync(PqcStage.Warn, ct);
        try
        {
            var response = await client.PostAsync("/.well-known/est/simpleenroll",
                new StringContent(TestCsrBuilder.BuildBase64Url("warned.example.com", []),
                    System.Text.Encoding.ASCII, "application/pkcs10"), ct);

            Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        }
        finally
        {
            await SetStageAsync(PqcStage.Off, ct);
        }
    }

    // The factory is shared by the class's tests, so a test that changes the stage restores it.
    private async Task SetStageAsync(PqcStage stage, CancellationToken ct)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        (await db.Settings.SingleAsync(ct)).PqcStage = stage;
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Simpleenroll_with_composite_csr_records_the_composite_algorithm()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildCompositeBase64Url("composite-device.example.com", [], "MLDSA87-Ed448-SHAKE256");

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = await db.CertificateRequests
            .SingleAsync(r => r.CommonName == "composite-device.example.com", ct);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa87Ed448Shake256, request.KeyAlgorithm);
    }

    [Fact]
    public async Task Simpleenroll_with_unsupported_key_type_returns_400()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildEd25519Base64Url("ed25519-device.example.com");

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.CertificateRequests
            .AnyAsync(r => r.CommonName == "ed25519-device.example.com", ct));
    }

    [Fact]
    public async Task Simpleenroll_with_an_ml_kem_key_returns_400()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildMlKemKeyedBase64Url("kem-device.example.com");

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.CertificateRequests
            .AnyAsync(r => r.CommonName == "kem-device.example.com", ct));
    }

    [Fact]
    public async Task Simplereenroll_without_client_certificate_returns_401()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient(); // no client cert configured
        var csr = TestCsrBuilder.BuildBase64Url(subjectCn: "renew1.example.com", sanDnsNames: []);

        var response = await client.PostAsync("/.well-known/est/simplereenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Simplereenroll_with_an_unrelated_dns_san_is_refused_before_creating_a_request()
    {
        // mTLS proves control of the presented certificate, not every identity in a new CSR. A
        // matching CN must not let that certificate add an unrelated DNS SAN under autoapproval.
        var ct = TestContext.Current.CancellationToken;
        await DeleteRequestsForCommonNameAsync("Est Test CA", ct); // the class fixture is shared; a sibling may have left one
        using var client = _factory.CreateClient();
        using var presentedCertificate = X509Certificate2.CreateFromPem(
            _factory.Services.GetRequiredService<ICertificateGenerator>().GetCaCertificatePem());
        using var presented = _factory.PresentClientCertificate(presentedCertificate);
        var csr = TestCsrBuilder.BuildBase64Url("Est Test CA", ["attacker.example.test"]);

        using (var scope = _factory.Services.CreateScope())
        {
            var certRequests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
            var settings = await certRequests.GetSettingsAsync(ct);
            settings.EstAutoApprove = true;
            await certRequests.SetupOrUpdateSettingsAsync(settings, "test-fixture", ct);
        }

        var response = await client.PostAsync("/.well-known/est/simplereenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        using var assertionScope = _factory.Services.CreateScope();
        var db = assertionScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.False(await db.CertificateRequests.AnyAsync(
            request => request.CommonName == "Est Test CA", ct));
    }

    [Fact]
    public async Task Simplereenroll_with_unchanged_identity_accepts_a_new_csr_key()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateClient();
        using var presentedCertificate = X509Certificate2.CreateFromPem(
            _factory.Services.GetRequiredService<ICertificateGenerator>().GetCaCertificatePem());
        using var presented = _factory.PresentClientCertificate(presentedCertificate);
        var csr = TestCsrBuilder.BuildBase64Url("Est Test CA", []);

        var response = await client.PostAsync("/.well-known/est/simplereenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        await DeleteRequestsForCommonNameAsync("Est Test CA", ct);
    }

    [Fact]
    public async Task Simpleenroll_retry_after_issuance_returns_the_existing_pkcs7_response()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var csr = TestCsrBuilder.BuildBase64Url("completed-retry.example.test", []);

        var initial = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);

        await MarkCsrRequestIssuedAsync(csr, ct);

        var retry = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal("application/pkcs7-mime", retry.Content.Headers.ContentType!.MediaType);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CsrPem == csr, ct));
    }

    [Fact]
    public async Task Simplereenroll_retry_after_issuance_returns_the_existing_pkcs7_response()
    {
        var ct = TestContext.Current.CancellationToken;
        await DeleteRequestsForCommonNameAsync("Est Test CA", ct);
        using var client = _factory.CreateClient();
        using var presentedCertificate = X509Certificate2.CreateFromPem(
            _factory.Services.GetRequiredService<ICertificateGenerator>().GetCaCertificatePem());
        using var presented = _factory.PresentClientCertificate(presentedCertificate);
        var csr = TestCsrBuilder.BuildBase64Url("Est Test CA", []);

        await SetEstAutoApproveAsync(false, ct);
        var initial = await client.PostAsync("/.well-known/est/simplereenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);
        Assert.Equal(HttpStatusCode.Accepted, initial.StatusCode);

        await MarkCsrRequestIssuedAsync(csr, ct);

        var retry = await client.PostAsync("/.well-known/est/simplereenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal("application/pkcs7-mime", retry.Content.Headers.ContentType!.MediaType);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CsrPem == csr, ct));
        await DeleteRequestsForCommonNameAsync("Est Test CA", ct);
    }

    [Fact]
    public async Task Simpleenroll_new_csr_for_an_issued_name_creates_a_renewal()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient(estAutoApprove: true);
        var firstCsr = TestCsrBuilder.BuildBase64Url("new-csr-retry.example.test", []);
        var newCsr = TestCsrBuilder.BuildBase64Url("new-csr-retry.example.test", []);

        await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(firstCsr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);
        await MarkCsrRequestIssuedAsync(firstCsr, ct);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(newCsr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(2, await db.CertificateRequests.CountAsync(request => request.CommonName == "new-csr-retry.example.test", ct));
    }

    [Fact]
    public async Task Simpleenroll_new_csr_for_a_pending_name_is_refused()
    {
        var ct = TestContext.Current.CancellationToken;
        using var client = _factory.CreateAuthenticatedClient();
        var firstCsr = TestCsrBuilder.BuildBase64Url("pending-new-csr.example.test", []);
        var newCsr = TestCsrBuilder.BuildBase64Url("pending-new-csr.example.test", []);

        await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(firstCsr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        var response = await client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(newCsr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CommonName == "pending-new-csr.example.test", ct));
    }

    [Fact]
    public async Task Simpleenroll_retry_does_not_return_another_credentials_certificate()
    {
        var ct = TestContext.Current.CancellationToken;
        using var owner = _factory.CreateAuthenticatedClient(estAutoApprove: true);
        var csr = TestCsrBuilder.BuildBase64Url("credential-isolation.example.test", []);

        await owner.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);
        await MarkCsrRequestIssuedAsync(csr, ct);

        await _factory.SeedCredentialAsync("other-device", "other-password", ct);
        using var other = _factory.CreateClient();
        var basic = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("other-device:other-password"));
        other.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", basic);

        var response = await other.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(csr, System.Text.Encoding.ASCII, "application/pkcs10"), ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(1, await db.CertificateRequests.CountAsync(request => request.CsrPem == csr, ct));
    }

    private async Task SetEstAutoApproveAsync(bool enabled, CancellationToken ct)
    {
        using var scope = _factory.Services.CreateScope();
        var certRequests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        var settings = await certRequests.GetSettingsAsync(ct);
        settings.EstAutoApprove = enabled;
        await certRequests.SetupOrUpdateSettingsAsync(settings, "test-fixture", ct);
    }

    private async Task MarkCsrRequestIssuedAsync(string csr, CancellationToken ct)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = await db.CertificateRequests.SingleAsync(candidate => candidate.CsrPem == csr, ct);
        var certRequests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        if (request.Status == CertificateRequestStatus.Pending)
            Assert.NotNull(await certRequests.MarkAsApprovedAsync(request.Id, "test-fixture", ct));
        using var certificate = TestCertificates.CreateSelfSigned("CN=EST polling result");
        await certRequests.MarkAsIssuedAsync(request.Id, new GeneratedCertificate
        {
            CertificatePem = certificate.ExportCertificatePem(),
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        }, cancellationToken: ct);
    }

    private async Task DeleteRequestsForCommonNameAsync(string commonName, CancellationToken ct)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.CertificateRequests
            .Where(request => request.CommonName == commonName)
            .ExecuteDeleteAsync(ct);
    }
}
