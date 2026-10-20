using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Qertum.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Qertum.Tests;

public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Context.Request.Headers.Authorization.ToString();

        if (header.StartsWith("Test-NoRole", StringComparison.Ordinal))
        {
            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "Regular User")], "Test");
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), "Test")));
        }

        // "Test-Role <role>": a non-admin identity whose permissions come from seeded RolePermissions rows.
        if (header.StartsWith("Test-Role ", StringComparison.Ordinal))
        {
            var role = header["Test-Role ".Length..].Trim();
            var roleClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, $"{role} user"),
                new Claim(ClaimTypes.NameIdentifier, $"sub-{role}"),
                new Claim(ClaimTypes.Role, role)
            };
            var displayName = Context.Request.Headers["X-Test-Display-Name"].ToString();
            if (!string.IsNullOrWhiteSpace(displayName))
                roleClaims.Add(new Claim("preferred_username", displayName));
            var roleIdentity = new ClaimsIdentity(roleClaims, "Test");
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(roleIdentity), "Test")));
        }

        // "Test-Sub <sub> [role]": an identity with a stable subject (admin unless a role is given), for tests that
        // need two different people.
        if (header.StartsWith("Test-Sub ", StringComparison.Ordinal))
        {
            var parts = header["Test-Sub ".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var role = parts.Length > 1 ? parts[1] : "admin";
            var subClaims = new List<Claim>
            {
                new(ClaimTypes.Name, parts[0]), new("preferred_username", parts[0]), new(ClaimTypes.NameIdentifier, parts[0]), new(ClaimTypes.Role, role)
            };
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(subClaims, "Test")), "Test")));
        }

        // "Test-StepUp acr=<v> auth_time=<unix>": an admin whose token carries the step-up claims it is given.
        if (header.StartsWith("Test-StepUp", StringComparison.Ordinal))
        {
            var stepUpClaims = new List<Claim>
            {
                new(ClaimTypes.Name, "Test User"), new(ClaimTypes.NameIdentifier, "sub-stepup"), new(ClaimTypes.Role, "admin")
            };
            foreach (var pair in header["Test-StepUp".Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = pair.Split('=', 2);
                if (parts.Length == 2 && parts[0] != "none")
                    stepUpClaims.Add(new Claim(parts[0], parts[1]));
            }

            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity(stepUpClaims, "Test")), "Test")));
        }

        if (header.StartsWith("Test", StringComparison.Ordinal))
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, "Test User"),
                new Claim(ClaimTypes.Role, "admin")
            };
            var identity = new ClaimsIdentity(claims, "Test");
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), "Test")));
        }

        return Task.FromResult(AuthenticateResult.NoResult());
    }
}

/// <summary>
/// ApiService integration tests. Each test gets its own in-memory database via a
/// dedicated WebApplicationFactory so tests cannot see each other's rows.
/// </summary>
public sealed class ApiServiceTests
{
    internal static WebApplicationFactory<ApiServiceProgram> CreateFactory()
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                database.ReplaceDbContext(services);

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                // Replace the real CertificateGenerator with a stub so the approval guard
                // does not block tests that run without actual CA files on disk.
                services.AddSingleton<ICertificateGenerator>(new InitializedCertificateGeneratorStub());
            });
        });
    }

    internal static async Task EnsureDbAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct, bool seedSettings = true)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
        // The CA default is PQC stage Enforce; these tests issue RSA certificates and are not about
        // the stage, so they start from Off. Tests about the stage set their own.
        if (seedSettings && !await db.Settings.AnyAsync(ct))
        {
            db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
            await db.SaveChangesAsync(ct);
        }
    }

    [Fact]
    public async Task GetSettings_WithoutAuth_Returns401()
    {
        await using var factory = CreateFactory();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var response = await client.GetAsync("/v1/settings", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetSettings_WithAuth_ReturnsCorrectShape()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/v1/settings", ct);
        Assert.True(response.IsSuccessStatusCode, $"Expected 200, got {response.StatusCode}");
        var settings = await response.Content.ReadFromJsonAsync<CaSettings>(ct);
        Assert.NotNull(settings);
    }

    [Fact]
    public async Task CreateCertificateRequest_InvalidCnCharacters_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "foo=bar",
            RequestedBy = "test@test.local",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task GetCertificateRequest_NonExistentId_Returns404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}", ct);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ApproveCertificateRequest_AlreadyApproved_Returns409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        // Create and approve once
        var createResponse = await client.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "approve-conflict.local",
            RequestedBy = "tester",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, ct);
        Assert.Equal(HttpStatusCode.Created, createResponse.StatusCode);
        var created = await createResponse.Content.ReadFromJsonAsync<CertificateRequest>(ct);
        Assert.NotNull(created);

        var firstApprove = await client.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, ct);
        Assert.Equal(HttpStatusCode.OK, firstApprove.StatusCode);

        // Try to approve again → 409
        var secondApprove = await client.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, ct);
        Assert.Equal(HttpStatusCode.Conflict, secondApprove.StatusCode);
    }

    [Fact]
    public async Task GetAuditLog_WithoutAdminRole_Returns403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");

        var response = await client.GetAsync("/v1/audit-log", ct);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task GetAuditCheckpoint_AsAdmin_ReturnsTheChainsArray_AndWithoutAdminRoleIs403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var ok = await admin.GetAsync("/v1/audit-log/checkpoint", ct);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var body = await ok.Content.ReadFromJsonAsync<AuditCheckpoint>(ct);
        Assert.NotNull(body);
        Assert.NotNull(body.Chains);
        Assert.NotEqual(default, body.GeneratedAtUtc);

        var other = factory.CreateClient();
        other.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");
        Assert.Equal(HttpStatusCode.Forbidden, (await other.GetAsync("/v1/audit-log/checkpoint", ct)).StatusCode);
    }

    [Fact]
    public async Task CreateDuplicateCertificateRequest_SameCn_Returns409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var payload = new
        {
            CommonName = "dup.local",
            RequestedBy = "tester",
            Type = "WebServer",
            PropertiesJson = "{}"
        };

        var first = await client.PostAsJsonAsync("/v1/certificate-requests", payload, ct);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);

        var second = await client.PostAsJsonAsync("/v1/certificate-requests", payload, ct);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task DeleteIssuedCertificateRequest_Returns409AndPreservesRecord()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var request = new CertificateRequest
        {
            Id = Guid.NewGuid(),
            CommonName = "delete-issued-conflict.local",
            RequestedBy = "tester",
            Type = "WebServer",
            Status = CertificateRequestStatus.Issued,
            SerialNumber = "DE1E7E"
        };
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.CertificateRequests.Add(request);
            await db.SaveChangesAsync(ct);
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var response = await client.DeleteAsync($"/v1/certificate-requests/{request.Id}", ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("Issued", await response.Content.ReadAsStringAsync(ct));
        using var assertionScope = factory.Services.CreateScope();
        var assertionDb = assertionScope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.NotNull(await assertionDb.CertificateRequests.FindAsync([request.Id], ct));
    }

    [Theory]
    [InlineData("Approved")]
    [InlineData("Issued")]
    public async Task CreateCertificateRequest_CallerSuppliedStatus_IsIgnoredAndRowStartsPending(string suppliedStatus)
    {
        // A caller with certificates.create must not be able to skip approval by naming a later
        // state in the body. The test identity is admin, which is the strongest case: even admin
        // approval goes through /approve so it is audited and AutoRevokeOnRenewal runs.
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = $"status-override-{suppliedStatus.ToLowerInvariant()}.local",
            Type = "WebServer",
            PropertiesJson = "{}",
            Status = suppliedStatus
        }, ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CertificateRequest>(ct);
        Assert.NotNull(created);
        Assert.Equal(CertificateRequestStatus.Pending, created.Status);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var stored = await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Pending, stored.Status);
    }
}

/// <summary>Stub used in unit tests — reports the CA as already initialized so the
/// approval guard does not block tests that run without real CA files on disk.</summary>
file sealed class InitializedCertificateGeneratorStub : ICertificateGenerator
{
    public bool IsInitialized => true;

    public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
    public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];

    public byte[] GenerateOcspResponse(
        byte[] derRequest,
        IReadOnlyDictionary<string, OcspCertificateStatus> statuses,
        CaSettings? caSettings = null) => [];


    public string GetCaCertificatePem() =>
        "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----";

    public GeneratedCertificate GenerateCertificate(
        CertificateRequest request,
        CaSettings? caSettings,
        CertificateTemplate? template = null) =>
        new()
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        };

    public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => [];
    public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => [];

    public GeneratedCertificate GenerateCa(GenerateCaRequest request) =>
        new()
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----",
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(10)
        };

    public void ImportCa(ImportCaRequest request) { }

    public GeneratedCertificate GenerateFromCsr(
        string csrDerBase64Url,
        CertificateRequest request,
        CaSettings? caSettings,
        CertificateTemplate? template = null) =>
        new()
        {
            CertificatePem = "-----BEGIN CERTIFICATE-----\nfake-csr\n-----END CERTIFICATE-----",
            PrivateKeyPem = string.Empty,
            ValidFrom = DateTime.UtcNow,
            ValidTo = DateTime.UtcNow.AddYears(1)
        };
}
