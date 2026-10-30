using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

// ReSharper disable AccessToDisposedClosure

namespace Qertum.Tests;

// ── Stubs ─────────────────────────────────────────────────────────────────────

file sealed class AcmeAlwaysSucceedVerifier : IAcmeChallengeVerifier
{
    public Task<AcmeVerificationResult> VerifyHttp01Async(
        string domain, string token, string accountKeyThumbprint, CancellationToken ct = default)
        => Task.FromResult(AcmeVerificationResult.Valid);

    public Task<AcmeVerificationResult> VerifyDns01Async(
        string baseDomain, string token, string accountKeyThumbprint, CancellationToken ct = default)
        => Task.FromResult(AcmeVerificationResult.Valid);
}

file sealed class AcmeAlwaysFailVerifier : IAcmeChallengeVerifier
{
    public Task<AcmeVerificationResult> VerifyHttp01Async(
        string domain, string token, string accountKeyThumbprint, CancellationToken ct = default)
        => Task.FromResult(AcmeVerificationResult.Failed(AcmeChallengeFailure.ConnectionFailed, "connection refused"));

    public Task<AcmeVerificationResult> VerifyDns01Async(
        string baseDomain, string token, string accountKeyThumbprint, CancellationToken ct = default)
        => Task.FromResult(AcmeVerificationResult.Failed(AcmeChallengeFailure.DnsNoTxtRecord, "no TXT record"));
}

file sealed class AcmeStubCertGenerator : ICertificateGenerator
{
    public bool IsInitialized => true;
    public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
    public string GetCaCertificatePem() => "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----";
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
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake-acme-csr\n-----END CERTIFICATE-----",
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
}

// ── Tests ─────────────────────────────────────────────────────────────────────

public sealed class AcmeProtocolTests
{
    [Theory]
    [InlineData("body")]
    [InlineData("payload")]
    [InlineData("jwk")]
    public async Task OversizedJwsInput_ReturnsPayloadTooLarge(string part)
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = CreateFactory();
        using var client = factory.CreateClient();
        var nonceResponse = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/acme/new-nonce"), ct);
        var nonce = nonceResponse.Headers.GetValues("Replay-Nonce").Single();
        var jwk = part == "jwk" ? new { kty = "EC", crv = "P-256", x = new string('A', 17_000), y = "AA" } : null;
        var header = JsonSerializer.Serialize(new { alg = "ES256", nonce, url = "http://localhost/acme/new-account", jwk });
        var protectedB64 = JwkConverter.Base64UrlEncode(Encoding.UTF8.GetBytes(header));
        var payloadB64 = part == "payload"
            ? JwkConverter.Base64UrlEncode(Encoding.UTF8.GetBytes(new string('A', EnrollmentPayloadLimits.DecodedPayloadBytes + 1)))
            : "";
        var body = part == "body"
            ? new string(' ', EnrollmentPayloadLimits.AcmeBodyBytes + 1)
            : JsonSerializer.Serialize(new { @protected = protectedB64, payload = payloadB64, signature = "AA" });

        var response = await client.PostAsync("/acme/new-account",
            new StringContent(body, Encoding.UTF8, "application/jose+json"), ct);

        Assert.Equal(System.Net.HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    private static WebApplicationFactory<AcmeServiceProgram> CreateFactory(
        IAcmeChallengeVerifier? verifier = null,
        IReadOnlyDictionary<string, string>? settings = null,
        Lifecycle.RecordingDiagnosticEventLog? diagnostics = null)
    {
        // Schema created BEFORE the host starts: AcmeChallengeVerificationService polls as soon as
        // the host starts, and racing EnsureCreated it intermittently hit "no such table", which could
        // delay challenge processing past PollOrderAsync's 10-second window.
        var database = SharedInMemoryDatabase.Create(createSchema: true);

        var factory = new WebApplicationFactory<AcmeServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.UseSetting("Acme:BaseUrl", "http://localhost");
            foreach (var (key, value) in settings ?? new Dictionary<string, string>())
                builder.UseSetting(key, value);
            builder.ConfigureTestServices(services =>
            {
                // A connection per context, never one shared object: the challenge verifier writes on its
                // own scope while the handlers under test read on theirs, and one SqliteConnection used
                // from both threads answered "database is locked". See SharedInMemoryDatabase.
                database.ReplaceDbContext(services);

                // Each factory gets its own key ring. The connection string is an in-memory SQLite
                // database with no directory, so AddCustomCaServices falls back to a machine-global
                // DataProtection-Keys folder shared by every test class running in parallel — which
                // makes anything encrypted at rest (EAB MAC keys) decrypt only by luck.
                services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();

                services.AddSingleton<ICertificateGenerator>(new AcmeStubCertGenerator());
                services.AddSingleton(verifier ?? new AcmeAlwaysSucceedVerifier());
                if (diagnostics is not null)
                    services.AddSingleton<IDiagnosticEventLog>(diagnostics);
            });
        });
        return factory;
    }

    [Fact]
    public async Task UnexpectedServerError_IsLoggedNotOnlyReturned()
    {
        // HandleAcme turns an unexpected exception into a serverInternal problem. Before this the
        // cause went only into the response body, so a production 500 left nothing in the log —
        // and ACME clients typically show just "server error".
        var ct = TestContext.Current.CancellationToken;
        var logs = new CapturingLoggerProvider();
        await using var factory = CreateFactory();
        await using var logged = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton<ILoggerProvider>(logs)));
        using var client = new AcmeTestClient(logged.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        // A genuine server-side fault: the table new-order writes to is gone.
        using (var scope = logged.Services.CreateScope())
            await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
                .Database.ExecuteSqlRawAsync("DROP TABLE AcmeChallenges", ct);

        // Routing is case-insensitive, so the request path is the client's spelling, not the route's.
        var resp = await client.PostAsync("/acme/NEW-ORDER", new
        {
            identifiers = new[] { new { type = "dns", value = "broken.local" } }
        }, ct);

        Assert.Equal(HttpStatusCode.InternalServerError, resp.StatusCode);
        // The cause goes to the log, not to the client: an exception message can name tables,
        // files or other internals.
        Assert.DoesNotContain("AcmeChallenges", await resp.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);
        // EF Core logs the failed command itself; what matters is that the ACME layer records
        // which endpoint turned it into a 500.
        var entry = Assert.Single(logs.Entries, e => e.Category == AcmeEndpointMappings.LogCategory);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.IsType<SqliteException>(entry.Exception?.GetBaseException());
        // The route template, never the client-chosen path (which could carry a decoded %0A).
        Assert.Contains("/acme/new-order", entry.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("NEW-ORDER", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClientError_IsNotLoggedAsAServerError()
    {
        // An AcmeException is the client's problem (bad nonce, malformed request): answering it is
        // normal operation, and logging it at error level would bury real faults.
        var ct = TestContext.Current.CancellationToken;
        var logs = new CapturingLoggerProvider();
        await using var factory = CreateFactory();
        await using var logged = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton<ILoggerProvider>(logs)));
        using var client = new AcmeTestClient(logged.CreateClient());

        var resp = await client.PostWithNonceAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, nonce: "totally-invalid-nonce", ct);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.DoesNotContain(logs.Entries, e => e.Level >= LogLevel.Error);
    }

    [Theory]
    [InlineData("not-json", "malformed")]
    [InlineData("array", "malformed")]
    [InlineData("missing-signature", "malformed")]
    [InlineData("number-field", "malformed")]
    [InlineData("bad-base64", "malformed")]
    [InlineData("header-not-json", "malformed")]
    [InlineData("header-missing-alg", "malformed")]
    [InlineData("alg-none", "badSignatureAlgorithm")]
    [InlineData("nonce-not-string", "badNonce")]
    [InlineData("jwk-not-object", "malformed")]
    [InlineData("jwk-missing-members", "malformed")]
    [InlineData("jwk-unsupported-type", "badPublicKey")]
    public async Task MalformedJws_IsAClientError_NotAServerError(string variant, string expectedType)
    {
        // Anyone can send these without an account. Each one used to escape the parser as a .NET
        // exception and come back as a 500 carrying the exception text, logged at error level.
        var ct = TestContext.Current.CancellationToken;
        var logs = new CapturingLoggerProvider();
        await using var factory = CreateFactory();
        await using var logged = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton<ILoggerProvider>(logs)));
        using var client = logged.CreateClient();
        var nonceResponse = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/acme/new-nonce"), ct);
        var nonce = nonceResponse.Headers.GetValues("Replay-Nonce").Single();

        static string B64(string text) => JwkConverter.Base64UrlEncode(Encoding.UTF8.GetBytes(text));
        string Header(object jwk, object? nonceValue = null, string alg = "ES256") =>
            B64(JsonSerializer.Serialize(new { alg, nonce = nonceValue ?? nonce, url = "http://localhost/acme/new-account", jwk }));
        static string Jws(string protectedB64) =>
            JsonSerializer.Serialize(new { @protected = protectedB64, payload = "", signature = "AA" });
        var ecJwk = new { kty = "EC", crv = "P-256", x = "AA", y = "AA" };

        var body = variant switch
        {
            "not-json" => "not json",
            "array" => "[]",
            "missing-signature" => JsonSerializer.Serialize(new { @protected = Header(ecJwk), payload = "" }),
            "number-field" => JsonSerializer.Serialize(new { @protected = 5, payload = "", signature = "AA" }),
            "bad-base64" => Jws("!!"),
            "header-not-json" => Jws(B64("not json")),
            "header-missing-alg" => Jws(B64("{}")),
            "alg-none" => Jws(Header(ecJwk, alg: "none")),
            "nonce-not-string" => Jws(Header(ecJwk, nonceValue: 5)),
            "jwk-not-object" => Jws(Header("text")),
            "jwk-missing-members" => Jws(Header(new { kty = "EC" })),
            "jwk-unsupported-type" => Jws(Header(new { kty = "OKP", crv = "Ed25519", x = "AA" })),
            _ => throw new ArgumentOutOfRangeException(nameof(variant))
        };

        var response = await client.PostAsync("/acme/new-account",
            new StringContent(body, Encoding.UTF8, "application/jose+json"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        Assert.Equal($"urn:ietf:params:acme:error:{expectedType}", problem.RootElement.GetProperty("type").GetString());
        Assert.DoesNotContain(logs.Entries, e => e.Level >= LogLevel.Error);
    }

    [Theory]
    [InlineData("/acme/new-account", "not json", "malformed")]
    [InlineData("/acme/new-account", """{"onlyReturnExisting":"yes"}""", "malformed")]
    [InlineData("/acme/new-account", """{"termsOfServiceAgreed":"yes"}""", "malformed")]
    [InlineData("/acme/new-order", "{}", "malformed")]
    [InlineData("/acme/new-order", """{"identifiers":"example.com"}""", "malformed")]
    [InlineData("/acme/new-order", """{"identifiers":[{"type":5,"value":"example.com"}]}""", "malformed")]
    [InlineData("/acme/new-order", """{"identifiers":[{"type":"dns"}]}""", "malformed")]
    [InlineData("/acme/new-order", """{"identifiers":[{"type":"ip","value":"192.0.2.1"}]}""", "unsupportedIdentifier")]
    [InlineData("account", """{"status":5}""", "malformed")]
    [InlineData("/acme/revoke-cert", """{"certificate":5}""", "malformed")]
    public async Task SignedPayloadOfTheWrongShape_IsAClientError_NotAServerError(string url, string payloadJson, string expectedType)
    {
        // Validly signed, so it reaches the handler; the payload is still the client's to get right.
        var ct = TestContext.Current.CancellationToken;
        var logs = new CapturingLoggerProvider();
        await using var factory = CreateFactory();
        await using var logged = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s => s.AddSingleton<ILoggerProvider>(logs)));
        using var client = new AcmeTestClient(logged.CreateClient());
        if (url != "/acme/new-account")
        {
            var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
            client.AccountUrl = accountResp.Headers.Location!.ToString();
        }

        var response = await client.PostRawAsync(url == "account" ? client.AccountUrl! : url, payloadJson, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        Assert.Equal($"urn:ietf:params:acme:error:{expectedType}", problem.RootElement.GetProperty("type").GetString());
        Assert.DoesNotContain(logs.Entries, e => e.Level >= LogLevel.Error);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public System.Collections.Concurrent.ConcurrentQueue<(string Category, LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Entries);

        public void Dispose() { }

        private sealed class CapturingLogger(
            string category,
            System.Collections.Concurrent.ConcurrentQueue<(string, LogLevel, string, Exception?)> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                entries.Enqueue((category, logLevel, formatter(state, exception), exception));
        }
    }

    [Fact]
    public async Task TestHost_GivesEachScopeItsOwnDatabaseConnection()
    {
        // AcmeChallengeVerificationService writes on its own scope every two seconds while the
        // handlers under test read on theirs. One shared SqliteConnection object is not thread-safe:
        // when the two overlapped, the order poll answered 500 "SQLite Error 5: database is locked",
        // failing whichever full-flow test was polling at that moment.
        await using var factory = CreateFactory();

        using var first = factory.Services.CreateScope();
        using var second = factory.Services.CreateScope();
        var a = first.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().Database.GetDbConnection();
        var b = second.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().Database.GetDbConnection();

        Assert.NotSame(a, b);
        // Separate connections, one database: a row written on one is visible on the other.
        await SeedAutoApproveAsync(factory, TestContext.Current.CancellationToken);
        Assert.True(await second.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .Settings.AnyAsync(TestContext.Current.CancellationToken));
    }

    private static async Task SeedAutoApproveAsync(WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var settings = await db.Settings.FirstOrDefaultAsync(ct);
        if (settings is null)
            db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, AcmeAutoApprove = true });
        else
            settings.AcmeAutoApprove = true;
        await db.SaveChangesAsync(ct);
    }

    // ── Directory ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Directory_ReturnsAllRequiredEndpoints()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();


        var response = await factory.CreateClient().GetAsync("/acme/directory", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.True(json.TryGetProperty("newNonce", out _));
        Assert.True(json.TryGetProperty("newAccount", out _));
        Assert.True(json.TryGetProperty("newOrder", out _));
        Assert.True(json.TryGetProperty("revokeCert", out _));
    }

    // ── Account ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task NewAccount_Returns201_WithLocationHeader()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();


        using var client = new AcmeTestClient(factory.CreateClient());

        var resp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);

        Assert.Equal(HttpStatusCode.Created, resp.StatusCode);
        Assert.NotNull(resp.Headers.Location);
        Assert.Contains("/acme/account/", resp.Headers.Location.ToString());
    }

    [Fact]
    public async Task NewAccount_ExistingKey_Returns200()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();


        using var client = new AcmeTestClient(factory.CreateClient());
        var payload = new { termsOfServiceAgreed = true };

        var first = await client.PostAsync("/acme/new-account", payload, ct);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        var firstLocation = first.Headers.Location!.ToString();

        var second = await client.PostAsync("/acme/new-account", payload, ct);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(firstLocation, second.Headers.Location!.ToString());
    }

    // ── Full flow ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task FullFlow_WithAutoApprove_CertificateIssuedAndDownloadable()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var recorder = new MetricsRecorder(
            factory.Services.GetRequiredService<System.Diagnostics.Metrics.IMeterFactory>(), ProtocolMetrics.MeterName);

        await SeedAutoApproveAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());

        // 1 — Create account
        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        Assert.Equal(HttpStatusCode.Created, accountResp.StatusCode);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        // 2 — Create order
        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "acme-test.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;

        // 3 — Fetch authorization and trigger challenge
        var authzResp = await client.PostAsGetAsync(authzUrl, ct);
        Assert.Equal(HttpStatusCode.OK, authzResp.StatusCode);
        var authzJson = await authzResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;

        var triggerResp = await client.PostAsync(challengeUrl, new { }, ct);
        Assert.Equal(HttpStatusCode.OK, triggerResp.StatusCode);

        // 4 — Wait for background service to validate the challenge and set order to "ready"
        await PollOrderAsync(client, orderUrl, "ready", ct);

        // 5 — Finalize with a real CSR
        using var csrKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=acme-test.local", csrKey, HashAlgorithmName.SHA256);
        var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());

        var finalizeResp = await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);
        Assert.Equal(HttpStatusCode.OK, finalizeResp.StatusCode);

        // 6 — Simulate the queue consumer: mark the cert request as issued
        await IssuePendingCertRequestAsync(factory, ct);

        // 7 — Poll order until "valid" and get certificate URL
        var finalOrderJson = await PollOrderAsync(client, orderUrl, "valid", ct);
        var certUrl = finalOrderJson.GetProperty("certificate").GetString()!;

        // 8 — Download certificate
        var certResp = await client.PostAsGetAsync(certUrl, ct);
        Assert.Equal(HttpStatusCode.OK, certResp.StatusCode);
        var certPem = await certResp.Content.ReadAsStringAsync(ct);
        Assert.Contains("BEGIN CERTIFICATE", certPem);

        // The operator's view of the same flow: one order created, one validated challenge, one order valid.
        Assert.Equal(1, recorder.Sum("ca.acme.orders", ("outcome", "created")));
        Assert.Equal(1, recorder.Sum("ca.acme.challenges", ("outcome", "valid")));
        Assert.Equal(1, recorder.Sum("ca.acme.orders", ("outcome", "valid")));
    }

    [Fact]
    public async Task FullFlow_WithoutAutoApprove_FinalizeCreatesPendingRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        // AcmeAutoApprove stays false (default)

        using var client = new AcmeTestClient(factory.CreateClient());

        // Create account and order
        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "manual.local" } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;

        // Trigger and wait for challenge validation
        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
        await client.PostAsync(challengeUrl, new { }, ct);
        await PollOrderAsync(client, orderUrl, "ready", ct);

        // Finalize
        using var csrKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=manual.local", csrKey, HashAlgorithmName.SHA256);
        var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());
        await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);

        // Verify the cert request landed as Pending (not Approved)
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var req = await db.CertificateRequests.FirstAsync(ct);
        Assert.Equal(CertificateRequestStatus.Pending, req.Status);
        Assert.NotNull(req.CsrPem);

        // The identity comes from the validated order identifiers, not from the CSR. Reading them
        // back with the wrong casing used to leave both of these blank.
        Assert.Equal("manual.local", req.CommonName);
        Assert.Contains("manual.local", req.PropertiesJson);
    }

    [Fact]
    public async Task RepeatOrder_ForAlreadyIssuedDomain_FinalizesAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        await SeedAutoApproveAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        // An ACME client renews by placing a fresh order for the same domain while the
        // certificate it already holds is still Issued. Both rounds must succeed.
        async Task<Guid> OrderAndFinalizeAsync()
        {
            var orderResp = await client.PostAsync("/acme/new-order", new
            {
                identifiers = new[] { new { type = "dns", value = "renew.local" } }
            }, ct);
            Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);
            var orderUrl = orderResp.Headers.Location!.ToString();
            var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
            var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
            var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;

            var authzJson = await (await client.PostAsGetAsync(authzUrl, ct))
                .Content.ReadFromJsonAsync<JsonElement>(ct);
            var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
            await client.PostAsync(challengeUrl, new { }, ct);
            await PollOrderAsync(client, orderUrl, "ready", ct);

            using var csrKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
                "CN=renew.local", csrKey, HashAlgorithmName.SHA256);
            var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());

            var finalizeResp = await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);
            Assert.Equal(HttpStatusCode.OK, finalizeResp.StatusCode);

            await IssuePendingCertRequestAsync(factory, ct);
            var finalOrderJson = await PollOrderAsync(client, orderUrl, "valid", ct);
            return Guid.Parse(finalOrderJson.GetProperty("certificate").GetString()!.Split('/')[^1]);
        }

        var firstCertId = await OrderAndFinalizeAsync();
        var secondCertId = await OrderAndFinalizeAsync();

        Assert.NotEqual(firstCertId, secondCertId);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var requests = await db.CertificateRequests
            .Where(r => r.CommonName == "renew.local")
            .OrderBy(r => r.CreatedAtUtc)
            .ToListAsync(ct);
        Assert.Equal(2, requests.Count);
        Assert.Null(requests[0].RenewedFromId);
        Assert.Equal(requests[0].Id, requests[1].RenewedFromId);
    }

    // ── Challenge offering ────────────────────────────────────────────────────

    [Fact]
    public async Task NewOrder_PlainName_OffersBothChallengeTypes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "both.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);

        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var authzResp = await client.PostAsGetAsync(authzUrl, ct);
        var authzJson = await authzResp.Content.ReadFromJsonAsync<JsonElement>(ct);

        var types = authzJson.GetProperty("challenges").EnumerateArray()
            .Select(c => c.GetProperty("type").GetString())
            .ToList();

        Assert.Contains("http-01", types);
        Assert.Contains("dns-01", types);
        Assert.False(authzJson.TryGetProperty("wildcard", out _));

        // The unique index on AcmeChallenge.Token forbids sharing one value between the two.
        var tokens = authzJson.GetProperty("challenges").EnumerateArray()
            .Select(c => c.GetProperty("token").GetString())
            .ToList();
        Assert.Equal(2, tokens.Distinct().Count());
    }

    // ── Resource shape (RFC 8555 §7.1) ────────────────────────────────────────

    [Fact]
    public async Task Resources_CarryRfc3339Timestamps_AndOmitFieldsThatAreNotYetSet()
    {
        // certbot (acme/josepy) parses every timestamp with an RFC 3339 parser and crashes on a null
        // "validated" or on a time with no offset; both came from a real client run against this server.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "shape.local" } }
        }, ct);
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;

        // The authorization is read back from the database, where timestamps lose their DateTimeKind.
        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);

        Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", orderJson.GetProperty("expires").GetString());
        Assert.Matches(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$", authzJson.GetProperty("expires").GetString());
        Assert.False(orderJson.TryGetProperty("certificate", out _), "certificate is absent until the order is valid");
        foreach (var challenge in authzJson.GetProperty("challenges").EnumerateArray())
            Assert.False(challenge.TryGetProperty("validated", out _), "validated is absent until the challenge is valid");
    }

    [Fact]
    public async Task AValidatedChallenge_ReportsWhenItWasValidated_AsRfc3339()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "validated.local" } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync(challengeUrl, new { }, ct)).StatusCode);
        await PollOrderAsync(client, orderUrl, "ready", ct);

        var after = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var validated = after.GetProperty("challenges").EnumerateArray()
            .Where(c => c.TryGetProperty("validated", out _))
            .Select(c => c.GetProperty("validated").GetString())
            .ToList();

        var only = Assert.Single(validated);
        Assert.Matches(@"Z$", only);
    }

    [Fact]
    public async Task ChallengeResponse_LinksUpToItsAuthorization()
    {
        // RFC 8555 §7.5.1: certbot's acme library reads the authorization URL from this header and
        // stops with '"up" Link header missing' when it is absent.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "up.local" } }
        }, ct);
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;

        var trigger = await client.PostAsync(challengeUrl, new { }, ct);
        var again = await client.PostAsync(challengeUrl, new { }, ct);

        foreach (var response in new[] { trigger, again })
        {
            var link = Assert.Single(response.Headers.GetValues("Link"));
            Assert.Equal($"<{authzUrl}>;rel=\"up\"", link);
        }
    }

    [Fact]
    public async Task NewOrder_Wildcard_OffersDns01OnlyAndReportsTheBaseName()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "*.wild.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);

        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var authzResp = await client.PostAsGetAsync(authzUrl, ct);
        var authzJson = await authzResp.Content.ReadFromJsonAsync<JsonElement>(ct);

        var challenges = authzJson.GetProperty("challenges").EnumerateArray().ToList();
        Assert.Single(challenges);
        Assert.Equal("dns-01", challenges[0].GetProperty("type").GetString());

        // RFC 8555 §7.1.4: base name in the identifier, wildcard reported separately.
        Assert.Equal("wild.local", authzJson.GetProperty("identifier").GetProperty("value").GetString());
        Assert.True(authzJson.GetProperty("wildcard").GetBoolean());

        // The order still reports the identifier the client asked for.
        Assert.Equal("*.wild.local",
            orderJson.GetProperty("identifiers")[0].GetProperty("value").GetString());
    }

    [Fact]
    public async Task NewOrder_BaseNameAndWildcard_ProduceTwoAuthorizations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[]
            {
                new { type = "dns", value = "pair.local" },
                new { type = "dns", value = "*.pair.local" }
            }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);

        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal(2, orderJson.GetProperty("authorizations").GetArrayLength());
    }

    [Fact]
    public async Task NewOrder_WildcardWithDns01Disabled_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(
            settings: new Dictionary<string, string> { ["Acme:Dns01:Enabled"] = "false" });
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "*.disabled.local" } }
        }, ct);

        // Accepting it would create an order nothing can ever validate.
        Assert.Equal(HttpStatusCode.BadRequest, orderResp.StatusCode);
    }

    // ── Failure and expiry ────────────────────────────────────────────────────

    [Fact]
    public async Task ChallengeFailure_MarksAuthorizationAndOrderInvalid()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(new AcmeAlwaysFailVerifier());
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "unreachable.local" } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;

        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);

        // Every challenge, not just the first: an authorization offers both http-01 and dns-01, and
        // one exhausted challenge does not fail the authorization while a sibling is still viable.
        foreach (var challenge in authzJson.GetProperty("challenges").EnumerateArray())
            await client.PostAsync(challenge.GetProperty("url").GetString()!, new { }, ct);

        // Once no challenge can still succeed, the authorization and the order fail with them,
        // otherwise the client polls a "pending" order that can never progress.
        // Three attempts spaced by the service's 5-second retry delay, so this needs more than the
        // default polling window.
        await PollOrderAsync(client, orderUrl, "invalid", ct, timeoutMs: 40_000, allowInvalid: true);

        var finalAuthz = await (await client.PostAsGetAsync(authzUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("invalid", finalAuthz.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ExpiredAuthorization_IsReportedExpiredAndCannotBeTriggered()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "stale.local" } }
        }, ct);
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;

        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;

        await ExpireEverythingAsync(factory, ct);

        var expiredAuthz = await (await client.PostAsGetAsync(authzUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("expired", expiredAuthz.GetProperty("status").GetString());

        var triggerResp = await client.PostAsync(challengeUrl, new { }, ct);
        Assert.Equal(HttpStatusCode.BadRequest, triggerResp.StatusCode);
    }

    [Fact]
    public async Task ExpiredOrder_CannotBeFinalized()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        await SeedAutoApproveAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "late.local" } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;

        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
        await client.PostAsync(challengeUrl, new { }, ct);
        await PollOrderAsync(client, orderUrl, "ready", ct);

        // The order was validated, then left to rot past its expiry. Domain ownership can change in
        // that window, so the validation it carries must no longer buy a certificate.
        await ExpireEverythingAsync(factory, ct);

        using var csrKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=late.local", csrKey, HashAlgorithmName.SHA256);
        var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());

        var finalizeResp = await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);
        Assert.Equal(HttpStatusCode.BadRequest, finalizeResp.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Empty(await db.CertificateRequests.ToListAsync(ct));
    }

    [Fact]
    public async Task Finalize_AtEnforce_RejectsRsaCsr()
    {
        var ct = TestContext.Current.CancellationToken;
        var response = await FinalizeRsaCsrAtStageAsync(PqcStage.Enforce, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Finalize_AtWarn_IssuesRsaCsr()
    {
        var ct = TestContext.Current.CancellationToken;
        var response = await FinalizeRsaCsrAtStageAsync(PqcStage.Warn, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private async Task<HttpResponseMessage> FinalizeRsaCsrAtStageAsync(PqcStage stage, CancellationToken ct)
    {
        await using var factory = CreateFactory();

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var row = await db.Settings.SingleAsync(ct);
            row.AcmeAutoApprove = true;
            row.PqcStage = stage;
            await db.SaveChangesAsync(ct);
        }

        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "pqc-only.local" } }
        }, ct);
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;
        var orderUrl = orderResp.Headers.Location!.ToString();

        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
        await client.PostAsync(challengeUrl, new { }, ct);
        await PollOrderAsync(client, orderUrl, "ready", ct);

        using var rsaKey = RSA.Create(2048);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=pqc-only.local", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());

        return await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);
    }

    [Fact]
    public async Task Finalize_WithCompositeCsr_RecordsTheCompositeAlgorithm()
    {
        // A composite key signs an ordinary PKCS#10, so ACME carries it unchanged; detection must
        // name the exact combination, because it selects the issuing strategy.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await SeedAutoApproveAsync(factory, ct);

        var csrB64 = TestCsrBuilder.BuildCompositeBase64Url("composite-csr.local", ["composite-csr.local"], "MLDSA65-ECDSA-P256-SHA512");
        var finalizeResp = await FinalizeOrderAsync(factory, "composite-csr.local", csrB64, ct);

        Assert.Equal(HttpStatusCode.OK, finalizeResp.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = await db.CertificateRequests.SingleAsync(ct);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512, request.KeyAlgorithm);
    }

    [Fact]
    public async Task Finalize_WithMlDsaCsr_RecordsMlDsaAlgorithmEvenWhenPqcOnlyIsOff()
    {
        // The issued certificate's key usage is chosen from the request's KeyAlgorithm, so recording
        // an ML-DSA CSR as RSA makes BuildKeyUsageBits assert keyEncipherment/dataEncipherment on a
        // signature-only key — which RFC 9881 §5 forbids. Detection must not depend on the policy.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await SeedAutoApproveAsync(factory, ct);

        var csrB64 = TestCsrBuilder.BuildMlDsaBase64Url("pqc-csr.local", ["pqc-csr.local"]);
        var finalizeResp = await FinalizeOrderAsync(factory, "pqc-csr.local", csrB64, ct);

        Assert.Equal(HttpStatusCode.OK, finalizeResp.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = await db.CertificateRequests.SingleAsync(ct);
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65, request.KeyAlgorithm);
    }

    [Fact]
    public async Task Finalize_WithUnsupportedKeyTypeCsr_IsRefusedAsBadCsr()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await SeedAutoApproveAsync(factory, ct);

        var csrB64 = TestCsrBuilder.BuildEd25519Base64Url("ed25519.local");
        var finalizeResp = await FinalizeOrderAsync(factory, "ed25519.local", csrB64, ct);

        Assert.Equal(HttpStatusCode.BadRequest, finalizeResp.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Empty(await db.CertificateRequests.ToListAsync(ct));
    }

    // A KEM key cannot sign its CSR, so ACME cannot carry one; the CA-generated path is the only one.
    [Fact]
    public async Task Finalize_WithAnMlKemKeyedCsr_IsRefusedAsBadCsr()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await SeedAutoApproveAsync(factory, ct);

        var csrB64 = TestCsrBuilder.BuildMlKemKeyedBase64Url("kem.local");
        var finalizeResp = await FinalizeOrderAsync(factory, "kem.local", csrB64, ct);

        Assert.Equal(HttpStatusCode.BadRequest, finalizeResp.StatusCode);
        Assert.Contains("badCSR", await finalizeResp.Content.ReadAsStringAsync(ct), StringComparison.Ordinal);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Empty(await db.CertificateRequests.ToListAsync(ct));
    }

    /// <summary>Drives account → order → challenge → ready, then posts <paramref name="csrB64"/>
    /// to the order's finalize URL and returns that response.</summary>
    [Fact]
    public async Task AFailingChallenge_RecordsEachAttemptAndTheInvalidAuthorizationAgainstTheOrder()
    {
        var ct = TestContext.Current.CancellationToken;
        var diagnostics = new Lifecycle.RecordingDiagnosticEventLog();
        await using var factory = CreateFactory(new AcmeAlwaysFailVerifier(), diagnostics: diagnostics);
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var orderResp = await client.PostAsync("/acme/new-order",
            new { identifiers = new[] { new { type = "dns", value = "fails.local" } } }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderId = Guid.Parse(orderUrl[(orderUrl.LastIndexOf('/') + 1)..]);
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzJson = await (await client.PostAsGetAsync(orderJson.GetProperty("authorizations")[0].GetString()!, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        await client.PostAsync(Http01(authzJson).GetProperty("url").GetString()!, new { }, ct);

        // Three attempts five seconds apart; the dns-01 sibling stays pending, so the order itself
        // stays pending too. Wait for the third recorded attempt rather than for a status.
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline &&
               diagnostics.Entries.Count(e => e.Action == DiagnosticActions.ChallengeAttemptFailed) < 3)
            await Task.Delay(250, ct);

        var forOrder = diagnostics.Entries.Where(e => e.SubjectId == orderId).ToList();
        Assert.All(forOrder, e => Assert.Equal(LifecycleSubjectTypes.AcmeOrder, e.SubjectType));
        Assert.Contains(forOrder, e => e.Action == DiagnosticActions.OrderCreated);
        Assert.Contains(forOrder, e => e.Action == DiagnosticActions.ChallengeTriggered);
        var attempts = forOrder.Where(e => e.Action == DiagnosticActions.ChallengeAttemptFailed).ToList();
        Assert.Equal(3, attempts.Count);
        Assert.All(attempts, a => Assert.Equal(nameof(AcmeChallengeFailure.ConnectionFailed), a.Category));
        Assert.DoesNotContain(forOrder, e => (e.Detail ?? "").Contains(TokenOf(authzJson), StringComparison.Ordinal));
    }

    [Fact]
    public async Task AFinalizedOrder_RecordsFinalizedWithTheCertificateRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        var diagnostics = new Lifecycle.RecordingDiagnosticEventLog();
        await using var factory = CreateFactory(diagnostics: diagnostics);
        await SeedAutoApproveAsync(factory, ct);

        var response = await FinalizeOrderAsync(factory, "finalized.local",
            TestCsrBuilder.BuildEcdsaBase64Url("finalized.local", "P-256"), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        var requestId = (await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.SingleAsync(ct)).Id;
        var finalized = Assert.Single(diagnostics.Entries, e => e.Action == DiagnosticActions.Finalized);
        Assert.Contains(((Guid)requestId).ToString(), JsonSerializer.Serialize(finalized.Data));
    }

    [Fact]
    public async Task ANewOrderRefusedByPolicy_IsRecordedAgainstTheAccount()
    {
        var ct = TestContext.Current.CancellationToken;
        var diagnostics = new Lifecycle.RecordingDiagnosticEventLog();
        await using var factory = CreateFactory(diagnostics: diagnostics);
        await LinkWebServerPolicyAsync(factory, ct, dnsSuffixes: ["corp.example.com"]);
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var resp = await client.PostAsync("/acme/new-order",
            new { identifiers = new[] { new { type = "dns", value = "host.other.net" } } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var refused = Assert.Single(diagnostics.Entries, e => e.Action == DiagnosticActions.NewOrderRefused);
        Assert.Equal(LifecycleSubjectTypes.AcmeAccount, refused.SubjectType);
        Assert.Equal(DiagnosticCategories.OutsidePolicy, refused.Category);
    }

    private static string TokenOf(JsonElement authz) => Http01(authz).GetProperty("token").GetString()!;

    private static JsonElement Http01(JsonElement authz) =>
        authz.GetProperty("challenges").EnumerateArray().Single(c => c.GetProperty("type").GetString() == "http-01");

    // ── Issuance policy ───────────────────────────────────────────────────────

    private static async Task LinkWebServerPolicyAsync(WebApplicationFactory<AcmeServiceProgram> factory,
        CancellationToken ct, string[]? dnsSuffixes = null, string[]? algorithms = null)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await Policies.PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer",
            dnsSuffixes: dnsSuffixes, algorithms: algorithms, ct: ct);
    }

    [Fact]
    public async Task NewOrder_NameOutsideTheIssuersNameConstraints_IsRejectedIdentifier()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using (var scope = factory.Services.CreateScope())
        {
            // A registered default issuer that permits only allowed.local. LegacyFiles makes the
            // registry sign with the stub generator; only the constraint columns matter here.
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.Issuers.Add(new Issuer
            {
                Name = "Constrained", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
                Status = IssuerStatus.Active, IsDefault = true, LegacyFiles = true,
                CertificatePem = "stub", SpkiSha256 = "00", PermittedDnsSuffixesJson = "[\"allowed.local\"]",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(ct);
        }
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "host.other.local" } }
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, orderResp.StatusCode);
        var problem = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:rejectedIdentifier", problem.GetProperty("type").GetString());
    }

    [Fact]
    public async Task NewOrder_NameOutsideIssuancePolicy_IsRejectedBeforeAnOrderExists()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await LinkWebServerPolicyAsync(factory, ct, dnsSuffixes: ["allowed.local"]);
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "host.other.local" } }
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, orderResp.StatusCode);
        var problem = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:rejectedIdentifier", problem.GetProperty("type").GetString());
        using var verify = factory.Services.CreateScope();
        Assert.False(await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>().AcmeOrders.AnyAsync(ct));
    }

    [Fact]
    public async Task NewOrder_FollowsTheConfiguredAcmeTemplateKey()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1, ct);
            if (settings is null)
            {
                settings = new CaSettings { PqcStage = PqcStage.Off };
                db.Settings.Add(settings);
            }
            settings.AcmeTemplateTypeKey = "ClientAuth";
            await db.SaveChangesAsync(ct);
            // On ClientAuth, not WebServer: this only rejects if the configured key is honoured.
            await Policies.PolicySeeding.LinkPublishedPolicyAsync(db, "ClientAuth",
                dnsSuffixes: ["allowed.local"], ct: ct);
        }
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "host.other.local" } }
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, orderResp.StatusCode);
        var problem = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:rejectedIdentifier", problem.GetProperty("type").GetString());
    }

    [Fact]
    public async Task NewOrder_NameInsideIssuancePolicy_IsAccepted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await LinkWebServerPolicyAsync(factory, ct, dnsSuffixes: ["allowed.local"]);
        using var client = new AcmeTestClient(factory.CreateClient());
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "host.allowed.local" } }
        }, ct);

        Assert.Equal(HttpStatusCode.Created, orderResp.StatusCode);
    }

    [Fact]
    public async Task Finalize_KeyAlgorithmOutsideIssuancePolicy_IsBadCsrAndCreatesNoRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await LinkWebServerPolicyAsync(factory, ct, algorithms: ["ECDSA-P256"]);

        using var rsaKey = RSA.Create(2048);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=policy-algo.local", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var csrB64 = JwkConverter.Base64UrlEncode(x509Req.CreateSigningRequest());

        var response = await FinalizeOrderAsync(factory, "policy-algo.local", csrB64, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:badCSR", problem.GetProperty("type").GetString());
        using var verify = factory.Services.CreateScope();
        Assert.False(await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AnyAsync(r => r.CommonName == "policy-algo.local", ct));
    }

    private static async Task<HttpResponseMessage> FinalizeOrderAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, string domain, string csrB64, CancellationToken ct)
    {
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = domain } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderJson = await orderResp.Content.ReadFromJsonAsync<JsonElement>(ct);
        var authzUrl = orderJson.GetProperty("authorizations")[0].GetString()!;
        var finalizeUrl = orderJson.GetProperty("finalize").GetString()!;

        var authzJson = await (await client.PostAsGetAsync(authzUrl, ct)).Content.ReadFromJsonAsync<JsonElement>(ct);
        var challengeUrl = authzJson.GetProperty("challenges")[0].GetProperty("url").GetString()!;
        await client.PostAsync(challengeUrl, new { }, ct);
        await PollOrderAsync(client, orderUrl, "ready", ct);

        return await client.PostAsync(finalizeUrl, new { csr = csrB64 }, ct);
    }

    private static async Task ExpireEverythingAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var past = DateTime.UtcNow.AddMinutes(-1);
        await db.AcmeOrders.ExecuteUpdateAsync(s => s.SetProperty(o => o.ExpiresAtUtc, past), ct);
        await db.AcmeAuthorizations.ExecuteUpdateAsync(s => s.SetProperty(a => a.ExpiresAtUtc, past), ct);
    }

    // ── External account binding ──────────────────────────────────────────────

    [Fact]
    public async Task NewAccount_WhenBindingRequiredAndAbsent_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());
        var response = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:externalAccountRequired", problem.GetProperty("type").GetString());

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Empty(await db.AcmeAccounts.ToListAsync(ct));
    }

    [Fact]
    public async Task NewAccount_WithValidBinding_RegistersAndConsumesTheCredential()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, macKey) = await IssueEabCredentialAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());
        var response = await client.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = client.BuildEab(kid, macKey)
        }, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var account = await db.AcmeAccounts.SingleAsync(ct);
        Assert.Equal(kid, account.ExternalAccountKid);

        // The credential records which account it created, which is what makes it single-use.
        var credential = await db.AcmeExternalAccountKeys.SingleAsync(ct);
        Assert.Equal(account.Id, credential.BoundAccountId);
        Assert.NotNull(credential.BoundAtUtc);
    }

    [Fact]
    public async Task NewAccount_WithForgedBindingSignature_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, _) = await IssueEabCredentialAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());
        var wrongMac = new byte[32];
        Random.Shared.NextBytes(wrongMac);

        var response = await client.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = client.BuildEab(kid, wrongMac)
        }, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await AssertNoAccountsAsync(factory, ct);
    }

    [Fact]
    public async Task NewAccount_WithBindingCoveringADifferentKey_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, macKey) = await IssueEabCredentialAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());
        using var someoneElsesKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // A correctly signed binding, but it vouches for a different account key — replaying one
        // registration's binding must not register another key.
        var response = await client.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = client.BuildEab(kid, macKey, coveredJwk: AcmeTestClient.JwkObj(someoneElsesKey))
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoAccountsAsync(factory, ct);
    }

    [Fact]
    public async Task NewAccount_ReusingACredentialForASecondAccount_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, macKey) = await IssueEabCredentialAsync(factory, ct);

        using var first = new AcmeTestClient(factory.CreateClient());
        var firstResponse = await first.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = first.BuildEab(kid, macKey)
        }, ct);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        // One credential, one account: otherwise a single leaked key mints accounts indefinitely.
        using var second = new AcmeTestClient(factory.CreateClient());
        var secondResponse = await second.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = second.BuildEab(kid, macKey)
        }, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Single(await db.AcmeAccounts.ToListAsync(ct));
    }

    [Fact]
    public async Task NewAccount_WithDisabledCredential_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, macKey) = await IssueEabCredentialAsync(factory, ct, enabled: false);

        using var client = new AcmeTestClient(factory.CreateClient());
        var response = await client.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = client.BuildEab(kid, macKey)
        }, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await AssertNoAccountsAsync(factory, ct);
    }

    [Fact]
    public async Task NewAccount_BindingBoundToAnotherUrl_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await RequireExternalAccountBindingAsync(factory, ct);
        var (kid, macKey) = await IssueEabCredentialAsync(factory, ct);

        using var client = new AcmeTestClient(factory.CreateClient());
        var response = await client.PostAsync("/acme/new-account", new
        {
            termsOfServiceAgreed = true,
            externalAccountBinding = client.BuildEab(kid, macKey, urlOverride: "http://localhost/acme/key-change")
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoAccountsAsync(factory, ct);
    }

    [Fact]
    public async Task Directory_AdvertisesExternalAccountRequiredOnlyWhenItIs()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();

        var before = await (await factory.CreateClient().GetAsync("/acme/directory", ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.False(before.GetProperty("meta").TryGetProperty("externalAccountRequired", out _));

        await RequireExternalAccountBindingAsync(factory, ct);

        // §7.1.1: a client can then fail up front instead of after a rejected registration.
        var after = await (await factory.CreateClient().GetAsync("/acme/directory", ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.True(after.GetProperty("meta").GetProperty("externalAccountRequired").GetBoolean());
    }

    private static async Task RequireExternalAccountBindingAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var settings = await db.Settings.FirstOrDefaultAsync(ct);
        if (settings is null)
            db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, AcmeRequireExternalAccountBinding = true });
        else
            settings.AcmeRequireExternalAccountBinding = true;
        await db.SaveChangesAsync(ct);
    }

    private static async Task<(string Kid, byte[] MacKey)> IssueEabCredentialAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct, bool enabled = true)
    {
        using var scope = factory.Services.CreateScope();
        var svc = scope.ServiceProvider.GetRequiredService<Qertum.Services.Acme.IAcmeExternalAccountKeyService>();
        var created = await svc.CreateAsync("test credential", "test-runner", ct);

        if (!enabled)
            await svc.SetEnabledAsync(created.Credential.Id, false, "test-runner", ct);

        return (created.Credential.Kid, JwkConverter.Base64UrlDecode(created.MacKey));
    }

    private static async Task AssertNoAccountsAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Empty(await db.AcmeAccounts.ToListAsync(ct));
    }

    // ── Account ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Account_PostAsGet_ReturnsTheAccountItAuthenticatedAs()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true, contact = new[] { "mailto:admin@contoso.local" } }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        // The URL the server itself handed back in Location has to answer.
        var response = await client.PostAsGetAsync(client.AccountUrl, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("valid", json.GetProperty("status").GetString());
        Assert.Contains("mailto:admin@contoso.local", json.GetProperty("contact").ToString());
    }

    [Fact]
    public async Task Account_PostAsGet_ForSomeoneElsesAccount_IsUnauthorized()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());
        using var other = new AcmeTestClient(factory.CreateClient());

        var mine = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = mine.Headers.Location!.ToString();

        var theirs = await other.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        var theirUrl = theirs.Headers.Location!.ToString();

        // Signed as my account, asking for theirs: the kid and the path disagree.
        var response = await client.PostAsGetAsync(theirUrl, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Account_Update_ReplacesTheContactList()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true, contact = new[] { "mailto:old@contoso.local" } }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        // RFC 8555 §7.3.2: a non-empty payload on the account URL is an update, not a read.
        var response = await client.PostAsync(client.AccountUrl,
            new { contact = new[] { "mailto:new@contoso.local" } }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Contains("mailto:new@contoso.local", json.GetProperty("contact").ToString());
        Assert.DoesNotContain("mailto:old@contoso.local", json.GetProperty("contact").ToString());

        // And it persisted, rather than only being reflected in the response.
        var reread = await (await client.PostAsGetAsync(client.AccountUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Contains("mailto:new@contoso.local", reread.GetProperty("contact").ToString());
    }

    [Theory]
    [InlineData("https://contoso.local/webhook")]
    [InlineData("tel:+15551234")]
    public async Task Account_Update_NonMailtoContact_IsUnsupported(string contact)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        var response = await client.PostAsync(client.AccountUrl, new { contact = new[] { contact } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Contains("unsupportedContact", problem.GetProperty("type").GetString());
    }

    [Theory]
    [InlineData("mailto:not-an-address")]
    [InlineData("mailto:a@b.local?subject=hi")]
    [InlineData("mailto:one@b.local,two@b.local")]
    public async Task Account_Update_MalformedMailto_IsInvalidContact(string contact)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        // RFC 8555 §7.3: hfields are forbidden and a mailto must carry exactly one addr-spec.
        var response = await client.PostAsync(client.AccountUrl, new { contact = new[] { contact } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Contains("invalidContact", problem.GetProperty("type").GetString());
    }

    [Fact]
    public async Task Account_Deactivate_TakesEffectOnTheNextRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        var response = await client.PostAsync(client.AccountUrl, new { status = "deactivated" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("deactivated", json.GetProperty("status").GetString());

        // RFC 8555 §7.3.6: a deactivated account can no longer act. The parser rejects it, so this
        // covers every authenticated endpoint at once.
        var afterwards = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "after-deactivation.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, afterwards.StatusCode);
    }

    [Fact]
    public async Task Account_Deactivate_IsOneWay()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        await client.PostAsync(client.AccountUrl, new { status = "deactivated" }, ct);

        // Reactivation would undo the only revocation lever an account holder has.
        var response = await client.PostAsync(client.AccountUrl, new { status = "valid" }, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Account_Update_RejectsAStatusOtherThanDeactivated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        // §7.3.6 allows exactly one client-settable status. "revoked" is the server's to assign.
        var response = await client.PostAsync(client.AccountUrl, new { status = "revoked" }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Contains("malformed", problem.GetProperty("type").GetString());
    }

    // ── Account orders list ───────────────────────────────────────────────────

    [Fact]
    public async Task AccountOrders_ListsThisAccountsOrders()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        var first = await client.PostAsync("/acme/new-order",
            new { identifiers = new[] { new { type = "dns", value = "orders-one.local" } } }, ct);
        var second = await client.PostAsync("/acme/new-order",
            new { identifiers = new[] { new { type = "dns", value = "orders-two.local" } } }, ct);

        var accountJson = await (await client.PostAsGetAsync(client.AccountUrl, ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);

        // The account object advertises the list, and the URL it advertises has to answer.
        var ordersUrl = accountJson.GetProperty("orders").GetString()!;
        var response = await client.PostAsGetAsync(ordersUrl, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        var urls = json.GetProperty("orders").EnumerateArray().Select(o => o.GetString()).ToList();

        Assert.Contains(first.Headers.Location!.ToString(), urls);
        Assert.Contains(second.Headers.Location!.ToString(), urls);
        Assert.Equal(2, urls.Count);
    }

    [Fact]
    public async Task AccountOrders_DoesNotLeakAnotherAccountsOrders()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());
        using var other = new AcmeTestClient(factory.CreateClient());

        var mine = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = mine.Headers.Location!.ToString();

        var theirs = await other.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        other.AccountUrl = theirs.Headers.Location!.ToString();
        await other.PostAsync("/acme/new-order",
            new { identifiers = new[] { new { type = "dns", value = "theirs-only.local" } } }, ct);

        var minesOrders = await (await client.PostAsGetAsync($"{client.AccountUrl}/orders", ct))
            .Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Empty(minesOrders.GetProperty("orders").EnumerateArray());

        // Asking for their list while signed as me is the same mismatch the account URL rejects.
        var response = await client.PostAsGetAsync($"{other.AccountUrl}/orders", ct);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────

    [Fact]
    public async Task WriteEndpoints_OverTheLimit_AnswerRateLimitedProblem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(settings: new Dictionary<string, string>
        {
            ["Acme:RateLimits:WritePermitLimit"] = "2",
            ["Acme:RateLimits:WriteWindowSeconds"] = "60"
        });
        using var client = new AcmeTestClient(factory.CreateClient());

        for (var i = 0; i < 2; i++)
        {
            var allowed = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
            Assert.NotEqual(HttpStatusCode.TooManyRequests, allowed.StatusCode);
        }

        var rejected = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);

        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        // A bare 429 leaves a client retrying blind; it gets the ACME problem type it understands.
        var problem = await rejected.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("urn:ietf:params:acme:error:rateLimited", problem.GetProperty("type").GetString());
        Assert.NotNull(rejected.Headers.RetryAfter);
    }

    [Fact]
    public async Task PollingKeepsItsOwnAllowance_WhenTheWriteBudgetIsSpent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory(settings: new Dictionary<string, string>
        {
            ["Acme:RateLimits:WritePermitLimit"] = "1",
            ["Acme:RateLimits:WriteWindowSeconds"] = "60",
            ["Acme:RateLimits:PollingPermitLimit"] = "100"
        });
        using var client = new AcmeTestClient(factory.CreateClient());

        var created = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = created.Headers.Location!.ToString();

        var exhausted = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "limited.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.StatusCode);

        // Polling is what a correctly-behaving client does most of, so it must not be starved by the
        // creation budget being spent.
        var nonce = await factory.CreateClient().SendAsync(
            new HttpRequestMessage(HttpMethod.Head, "/acme/new-nonce"), ct);
        Assert.Equal(HttpStatusCode.OK, nonce.StatusCode);

        var account = await client.PostAsGetAsync(client.AccountUrl, ct);
        Assert.Equal(HttpStatusCode.OK, account.StatusCode);
    }

    // ── Key change ────────────────────────────────────────────────────────────

    [Fact]
    public async Task KeyChange_RotatesTheAccountKeyAndRetiresTheOldOne()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var accountId = Guid.Parse(client.AccountUrl.Split('/').Last());

        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var response = await client.PostKeyChangeAsync(newKey, ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // The account is the same account — same id, same orders — signed by a different key now.
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var stored = await db.AcmeAccounts.SingleAsync(a => a.Id == accountId, ct);
            Assert.Contains(JsonSerializer.Serialize(AcmeTestClient.JwkObj(newKey))[..20], stored.PublicKeyJwk);
        }

        // The old key must no longer authenticate: that is the entire point of a rollover. Checked
        // against new-order because the account URL itself has no handler to answer.
        var withOldKey = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "stale-key.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Unauthorized, withOldKey.StatusCode);

        client.AdoptKey(newKey);
        var withNewKey = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "rotated.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, withNewKey.StatusCode);
    }

    [Fact]
    public async Task KeyChange_InnerJwsSignedByTheWrongKey_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var impostor = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // The inner JWS advertises newKey but is signed by another key, so nobody has proved control
        // of the key the account would move to.
        var response = await client.PostKeyChangeAsync(newKey, ct, innerSigningKey: impostor);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await AssertAccountKeyUnchangedAsync(factory, client, ct);
    }

    [Fact]
    public async Task KeyChange_InnerUrlMismatch_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var response = await client.PostKeyChangeAsync(newKey, ct,
            innerUrlOverride: "http://localhost/acme/new-account");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertAccountKeyUnchangedAsync(factory, client, ct);
    }

    [Fact]
    public async Task KeyChange_StaleOldKey_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        using var newKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var strangerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // oldKey names a key this account never had, so this request cannot be a rotation of it.
        var response = await client.PostKeyChangeAsync(newKey, ct,
            oldKeyOverride: AcmeTestClient.JwkObj(strangerKey));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertAccountKeyUnchangedAsync(factory, client, ct);
    }

    [Fact]
    public async Task KeyChange_ToAKeyAnotherAccountHolds_Returns409WithThatAccount()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());
        using var other = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var otherResp = await other.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        var otherAccountUrl = otherResp.Headers.Location!.ToString();

        // RFC 8555 §7.3.5: point at the account already holding the key rather than merging them.
        var response = await client.PostKeyChangeAsync(other.Key, ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(otherAccountUrl, response.Headers.Location!.ToString());
        await AssertAccountKeyUnchangedAsync(factory, client, ct);
    }

    /// <summary>A rejected key-change must leave the account signing with exactly the key it had.</summary>
    private static async Task AssertAccountKeyUnchangedAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, AcmeTestClient client, CancellationToken ct)
    {
        var stillWorks = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "unchanged-key.local" } }
        }, ct);
        Assert.Equal(HttpStatusCode.Created, stillWorks.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var accountId = Guid.Parse(client.AccountUrl!.Split('/').Last());
        var stored = await db.AcmeAccounts.SingleAsync(a => a.Id == accountId, ct);
        Assert.Contains(JsonSerializer.Serialize(client.PublicJwk())[..20], stored.PublicKeyJwk);
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Revoke_SignedByCertificateKey_RevokesCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        // 1. Create a key and self-signed certificate
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-cert-1.local", certKey, HashAlgorithmName.SHA256);
        using var cert = x509Req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.RawData;
        var certB64Url = JwkConverter.Base64UrlEncode(certDer);

        // 2. Insert the issued certificate request in the DB
        var req = await InsertIssuedCertRequestAsync(factory, "revoke-cert-1.local", "acme:some-account-id", certDer, ct);

        // 3. Request revocation signed by the certificate's key (jwk header, kid is null)
        var payload = new { certificate = certB64Url, reason = 1 };
        var response = await client.PostRevocationAsync("/acme/revoke-cert", payload, certKey, null, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // 4. Verify request status in DB is PendingRevocation
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var updatedReq = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == req.Id, TestContext.Current.CancellationToken);
        Assert.Equal(CertificateRequestStatus.PendingRevocation, updatedReq!.Status);
        Assert.Equal("keyCompromise", updatedReq.RevocationReason);
    }

    [Fact]
    public async Task Revoke_WithForgedCertificateSharingStoredNameAndSerial_IsRefused()
    {
        // The certificate-key authorization must use the stored certificate's public key. If it
        // instead uses the submitted certificate, an attacker can copy the victim's name and
        // serial into a self-signed certificate and authorize revocation with their own key.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        using var victimKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var victimRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-forged.local", victimKey, HashAlgorithmName.SHA256);
        using var victimCertificate = victimRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var request = await InsertIssuedCertRequestAsync(
            factory, "revoke-forged.local", "acme:some-account-id", victimCertificate.RawData, ct);

        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forgedRequest = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-forged.local", attackerKey, HashAlgorithmName.SHA256);
        using var forgedCertificate = forgedRequest.Create(
            forgedRequest.SubjectName,
            System.Security.Cryptography.X509Certificates.X509SignatureGenerator.CreateForECDsa(attackerKey),
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddYears(1),
            victimCertificate.SerialNumberBytes.ToArray());

        var response = await client.PostRevocationAsync("/acme/revoke-cert",
            new { certificate = JwkConverter.Base64UrlEncode(forgedCertificate.RawData) }, attackerKey, null, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var stored = await db.CertificateRequests.SingleAsync(r => r.Id == request.Id, ct);
        Assert.Equal(CertificateRequestStatus.Issued, stored.Status);
    }

    [Fact]
    public async Task Revoke_SignedByIssuingAccountKey_RevokesCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        // Register the account
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var accountGuid = Guid.Parse(client.AccountUrl.Split('/').Last());

        // Create a key and self-signed certificate
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-cert-2.local", certKey, HashAlgorithmName.SHA256);
        using var cert = x509Req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.RawData;
        var certB64Url = JwkConverter.Base64UrlEncode(certDer);

        // Insert issued request belonging to this account
        var req = await InsertIssuedCertRequestAsync(factory, "revoke-cert-2.local", $"acme:{accountGuid}", certDer, ct);

        // Request revocation signed by the account key (kid header)
        var payload = new { certificate = certB64Url, reason = 4 };
        var response = await client.PostRevocationAsync("/acme/revoke-cert", payload, client.Key, client.AccountUrl, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var updatedReq = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == req.Id, TestContext.Current.CancellationToken);
        Assert.Equal(CertificateRequestStatus.PendingRevocation, updatedReq!.Status);
        Assert.Equal("superseded", updatedReq.RevocationReason);
    }

    [Fact]
    public async Task Revoke_SignedByAuthorizedAccountKey_RevokesCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        // Register the revoking account
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var accountGuid = Guid.Parse(client.AccountUrl.Split('/').Last());

        // Create a key and self-signed certificate
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-cert-3.local", certKey, HashAlgorithmName.SHA256);
        using var cert = x509Req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.RawData;
        var certB64Url = JwkConverter.Base64UrlEncode(certDer);

        // Insert issued request belonging to a DIFFERENT account
        var req = await InsertIssuedCertRequestAsync(factory, "revoke-cert-3.local", "acme:some-other-account", certDer, ct);

        // Seed valid authorization for the domain for our account
        await SeedValidAuthorizationAsync(factory, accountGuid, "revoke-cert-3.local", ct);

        // Request revocation signed by the revoking account key (kid header)
        var payload = new { certificate = certB64Url };
        var response = await client.PostRevocationAsync("/acme/revoke-cert", payload, client.Key, client.AccountUrl, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var updatedReq = await db.CertificateRequests.FirstOrDefaultAsync(r => r.Id == req.Id, TestContext.Current.CancellationToken);
        Assert.Equal(CertificateRequestStatus.PendingRevocation, updatedReq!.Status);
        Assert.Equal("unspecified", updatedReq.RevocationReason);
    }

    [Fact]
    public async Task Revoke_WithExpiredAuthorization_ReturnsUnauthorized()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();
        var accountGuid = Guid.Parse(client.AccountUrl.Split('/').Last());

        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-cert-5.local", certKey, HashAlgorithmName.SHA256);
        using var cert = x509Req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.RawData;
        var certB64Url = JwkConverter.Base64UrlEncode(certDer);

        var req = await InsertIssuedCertRequestAsync(factory, "revoke-cert-5.local", "acme:some-other-account", certDer, ct);

        // Proof of control that has aged out must not still authorize revoking someone else's
        // certificate for the name.
        await SeedValidAuthorizationAsync(factory, accountGuid, "revoke-cert-5.local", ct);
        await ExpireEverythingAsync(factory, ct);

        var response = await client.PostRevocationAsync("/acme/revoke-cert",
            new { certificate = certB64Url }, client.Key, client.AccountUrl, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var stored = await db.CertificateRequests.FirstAsync(r => r.Id == req.Id, ct);
        Assert.Equal(CertificateRequestStatus.Issued, stored.Status);
    }

    [Fact]
    public async Task Certificate_BeforeIssuance_IsNotFound()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        var accountResp = await client.PostAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        var orderResp = await client.PostAsync("/acme/new-order", new
        {
            identifiers = new[] { new { type = "dns", value = "nocert.local" } }
        }, ct);
        var orderUrl = orderResp.Headers.Location!.ToString();
        var orderId = orderUrl.Split('/').Last();

        // No certificate exists yet, so this must not answer 200 with an empty body.
        var certResp = await client.PostAsGetAsync($"/acme/certificate/{orderId}", ct);
        Assert.Equal(HttpStatusCode.NotFound, certResp.StatusCode);
    }

    [Fact]
    public async Task Revoke_UnauthorizedKey_ReturnsUnauthorized()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        using var client = new AcmeTestClient(factory.CreateClient());

        // Register the account
        var accountResp = await client.PostAsync("/acme/new-account", new { termsOfServiceAgreed = true }, ct);
        client.AccountUrl = accountResp.Headers.Location!.ToString();

        // Create a key and self-signed certificate
        using var certKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var x509Req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=revoke-cert-4.local", certKey, HashAlgorithmName.SHA256);
        using var cert = x509Req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var certDer = cert.RawData;
        var certB64Url = JwkConverter.Base64UrlEncode(certDer);

        // Insert issued request belonging to a DIFFERENT account (and no authorizations seeded)
        var req = await InsertIssuedCertRequestAsync(factory, "revoke-cert-4.local", "acme:some-other-account", certDer, ct);

        // Request revocation signed by the account key (kid header)
        var payload = new { certificate = certB64Url };
        var response = await client.PostRevocationAsync("/acme/revoke-cert", payload, client.Key, client.AccountUrl, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void WildcardCertificateName_MatchesItsWildcardAuthorization()
    {
        // A certificate names "*.example.com"; the authorization that proved it stores
        // "example.com" with Wildcard = true. Matching the two is what keeps an account able to
        // revoke the wildcard certificate it just obtained.
        var auths = new[]
        {
            (Identifier: "example.com", Wildcard: true),
            (Identifier: "plain.example.com", Wildcard: false)
        };

        Assert.True(AcmeEndpointMappings.IsCoveredByAuthorizations("*.example.com", auths));
        Assert.True(AcmeEndpointMappings.IsCoveredByAuthorizations("plain.example.com", auths));

        // The base name is NOT covered by a wildcard authorization: "*.example.com" proves control
        // of the subdomains, and RFC 8555 keeps the two identifiers separate.
        Assert.False(AcmeEndpointMappings.IsCoveredByAuthorizations("example.com", auths));

        // A non-wildcard authorization must not satisfy a wildcard name.
        Assert.False(AcmeEndpointMappings.IsCoveredByAuthorizations("*.plain.example.com", auths));
    }

    // ── Nonce protection ─────────────────────────────────────────────────────

    [Fact]
    public async Task BadNonce_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();


        using var client = new AcmeTestClient(factory.CreateClient());

        // Send a JWS with a fabricated (never-issued) nonce
        var resp = await client.PostWithNonceAsync("/acme/new-account",
            new { termsOfServiceAgreed = true }, nonce: "totally-invalid-nonce", ct);

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync(ct);
        Assert.Contains("badNonce", body);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static async Task<JsonElement> PollOrderAsync(
        AcmeTestClient client, string orderUrl, string expectedStatus, CancellationToken ct,
        int timeoutMs = 10_000, bool allowInvalid = false)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            var resp = await client.PostAsGetAsync(orderUrl, ct);
            // Report the problem document, not just the status code: the ACME problem detail is
            // the only place a serverInternal error's cause appears.
            if (!resp.IsSuccessStatusCode)
                Assert.Fail($"Polling the order answered {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync(ct)}");
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>(ct);
            var status = json.GetProperty("status").GetString();
            if (status == expectedStatus) return json;
            if (status == "invalid" && !allowInvalid)
                Assert.Fail($"Order became 'invalid' while waiting for '{expectedStatus}'.");
            await Task.Delay(300, ct);
        }
        throw new TimeoutException($"Order did not reach '{expectedStatus}' within {timeoutMs}ms.");
    }

    private static async Task IssuePendingCertRequestAsync(
        WebApplicationFactory<AcmeServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var svc = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();

        var pending = await db.CertificateRequests
            .Where(r => r.Status == CertificateRequestStatus.Approved)
            .FirstAsync(ct);

        await svc.MarkAsIssuedAsync(pending.Id, new GeneratedCertificate
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nacme-issued\n-----END CERTIFICATE-----",
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        }, "test-runner", ct);
    }

    private static async Task<CertificateRequest> InsertIssuedCertRequestAsync(
        WebApplicationFactory<AcmeServiceProgram> factory,
        string commonName,
        string requestedBy,
        byte[] certDer,
        CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        
        var certPem = $"-----BEGIN CERTIFICATE-----\n{Convert.ToBase64String(certDer)}\n-----END CERTIFICATE-----";
        var req = new CertificateRequest
        {
            CommonName = commonName,
            RequestedBy = requestedBy,
            Status = CertificateRequestStatus.Issued,
            CertificatePem = certPem,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        };
        db.CertificateRequests.Add(req);
        await db.SaveChangesAsync(ct);
        return req;
    }

    private static async Task SeedValidAuthorizationAsync(
        WebApplicationFactory<AcmeServiceProgram> factory,
        Guid accountId,
        string identifierValue,
        CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        
        var order = new AcmeOrder
        {
            AccountId = accountId,
            IdentifiersJson = "[]",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7),
            Status = "valid"
        };
        db.AcmeOrders.Add(order);
        await db.SaveChangesAsync(ct);

        var auth = new AcmeAuthorization
        {
            OrderId = order.Id,
            IdentifierType = "dns",
            IdentifierValue = identifierValue,
            Status = "valid",
            ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
        };
        db.AcmeAuthorizations.Add(auth);
        await db.SaveChangesAsync(ct);
    }

    // ── Test ACME client ──────────────────────────────────────────────────────

    private sealed class AcmeTestClient : IDisposable
    {
        private readonly HttpClient _http;
        private ECDsa _key;

        public string? AccountUrl { get; set; }
        public ECDsa Key => _key;

        /// <summary>Starts signing with a rotated account key, as a client does after key-change.</summary>
        public void AdoptKey(ECDsa newKey) => _key = newKey;

        /// <summary>The current signing key as a JWK object, for payloads that must name a key.</summary>
        public object PublicJwk() => JwkObj(_key);

        /// <summary>
        /// Builds an externalAccountBinding JWS: HMAC over the account key being registered, keyed by
        /// the operator-issued MAC key (RFC 8555 §7.3.4).
        /// </summary>
        public object BuildEab(string kid, byte[] macKey, object? coveredJwk = null, string? urlOverride = null)
        {
            var header = new { alg = "HS256", kid, url = urlOverride ?? "http://localhost/acme/new-account" };
            var protB64 = B64U(J(header));
            var payloadB64 = B64U(J(coveredJwk ?? PublicJwk()));
            var mac = System.Security.Cryptography.HMACSHA256.HashData(
                macKey, Encoding.ASCII.GetBytes($"{protB64}.{payloadB64}"));

            return new { @protected = protB64, payload = payloadB64, signature = B64U(mac) };
        }

        public static object JwkObj(ECDsa key)
        {
            var p = key.ExportParameters(false);
            return new { kty = "EC", crv = "P-256", x = B64U(p.Q.X!), y = B64U(p.Q.Y!) };
        }

        /// <summary>
        /// Builds the two-layer key-change request: an inner JWS signed by the new key, wrapped in an
        /// outer JWS signed by the current account key. The overrides exist so a test can break one
        /// layer at a time.
        /// </summary>
        public Task<HttpResponseMessage> PostKeyChangeAsync(
            ECDsa newKey,
            CancellationToken ct,
            string? accountOverride = null,
            object? oldKeyOverride = null,
            string? innerUrlOverride = null,
            ECDsa? innerSigningKey = null)
        {
            var innerHeader = new
            {
                alg = "ES256",
                jwk = JwkObj(newKey),
                url = innerUrlOverride ?? "http://localhost/acme/key-change"
            };
            var innerPayload = new
            {
                account = accountOverride ?? AccountUrl,
                oldKey = oldKeyOverride ?? PublicJwk()
            };

            var innerProtB64 = B64U(J(innerHeader));
            var innerPayloadB64 = B64U(J(innerPayload));
            var innerSig = (innerSigningKey ?? newKey).SignData(
                Encoding.ASCII.GetBytes($"{innerProtB64}.{innerPayloadB64}"), HashAlgorithmName.SHA256);

            return PostAsync("/acme/key-change", new
            {
                @protected = innerProtB64,
                payload = innerPayloadB64,
                signature = B64U(innerSig)
            }, ct);
        }

        public AcmeTestClient(HttpClient http)
        {
            _http = http;
            _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        }

        public Task<HttpResponseMessage> PostAsync(string url, object payload, CancellationToken ct)
            => SendJwsAsync(url, B64U(J(payload)), ct);

        /// <summary>Signs exactly the given payload text, so a test can send JSON of the wrong shape.</summary>
        public Task<HttpResponseMessage> PostRawAsync(string url, string payloadJson, CancellationToken ct)
            => SendJwsAsync(url, B64U(payloadJson), ct);

        public Task<HttpResponseMessage> PostAsGetAsync(string url, CancellationToken ct)
            => SendJwsAsync(url, "", ct);

        public Task<HttpResponseMessage> PostWithNonceAsync(string url, object payload, string nonce, CancellationToken ct)
            => SendJwsInternalAsync(url, B64U(J(payload)), nonce, ct);

        public async Task<HttpResponseMessage> PostRevocationAsync(string url, object payload, ECDsa keyToSignWith, string? kidToUse, CancellationToken ct)
        {
            var resp = await _http.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/acme/new-nonce"), ct);
            var nonce = resp.Headers.GetValues("Replay-Nonce").First();

            var absUrl = url.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? url : $"http://localhost{url}";
            object header;
            if (kidToUse is null)
            {
                var p = keyToSignWith.ExportParameters(false);
                var jwk = new { kty = "EC", crv = "P-256", x = B64U(p.Q.X!), y = B64U(p.Q.Y!) };
                header = new { alg = "ES256", nonce, url = absUrl, jwk };
            }
            else
            {
                header = new { alg = "ES256", nonce, url = absUrl, kid = kidToUse };
            }

            var payloadB64 = B64U(J(payload));
            var protB64 = B64U(J(header));
            var sigInput = Encoding.ASCII.GetBytes($"{protB64}.{payloadB64}");
            var sig = keyToSignWith.SignData(sigInput, HashAlgorithmName.SHA256);
            var body = J(new { @protected = protB64, payload = payloadB64, signature = B64U(sig) });

            return await _http.PostAsync(url,
                new StringContent(body, Encoding.UTF8, "application/jose+json"), ct);
        }

        private async Task<HttpResponseMessage> SendJwsAsync(string url, string payloadB64, CancellationToken ct)
        {
            var resp = await _http.SendAsync(new HttpRequestMessage(HttpMethod.Head, "/acme/new-nonce"), ct);
            var nonce = resp.Headers.GetValues("Replay-Nonce").First();
            return await SendJwsInternalAsync(url, payloadB64, nonce, ct);
        }

        private Task<HttpResponseMessage> SendJwsInternalAsync(string url, string payloadB64, string nonce, CancellationToken ct)
        {
            var absUrl = url.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? url : $"http://localhost{url}";
            object header;
            if (AccountUrl is null)
                header = new { alg = "ES256", nonce, url = absUrl, jwk = PublicJwkObj() };
            else
                header = new { alg = "ES256", nonce, url = absUrl, kid = AccountUrl };

            var protB64 = B64U(J(header));
            var sigInput = Encoding.ASCII.GetBytes($"{protB64}.{payloadB64}");
            var sig = _key.SignData(sigInput, HashAlgorithmName.SHA256);
            var body = J(new { @protected = protB64, payload = payloadB64, signature = B64U(sig) });

            return _http.PostAsync(url,
                new StringContent(body, Encoding.UTF8, "application/jose+json"), ct);
        }

        private object PublicJwkObj() => JwkObj(_key);

        private static string J(object o) => JsonSerializer.Serialize(o);
        private static string B64U(byte[] b) => JwkConverter.Base64UrlEncode(b);
        private static string B64U(string s) => B64U(Encoding.UTF8.GetBytes(s));

        public void Dispose() => _key.Dispose();
    }
}
