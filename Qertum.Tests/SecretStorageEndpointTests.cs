using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class SecretStorageEndpointTests : IDisposable
{
    private readonly List<string> _tempDirectories = [];

    public void Dispose()
    {
        foreach (var dir in _tempDirectories)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    private string NewDataDirectory()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"secret-storage-endpoint-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _tempDirectories.Add(dir);
        return dir;
    }

    private WebApplicationFactory<ApiServiceProgram> CreateFactory(string dataDirectory)
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                var descriptors = services
                    .Where(d => d.ServiceType == typeof(DbContextOptions<CertificateRequestDbContext>)
                             || d.ServiceType == typeof(CertificateRequestDbContext)
                             || d.ServiceType == typeof(SecretStorageOptions))
                    .ToList();
                foreach (var d in descriptors) services.Remove(d);

                database.ReplaceDbContext(services);

                // Isolate the secret-storage directory per test — AddCustomCaServices resolves
                // SecretStorageOptions from the real connection string at builder time, before
                // this callback runs, so every test would otherwise share one physical
                // secret-storage.json/local.key on this machine.
                services.AddSingleton(new SecretStorageOptions { DataDirectory = dataDirectory });

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                services.AddSingleton<ICertificateGenerator>(new LocalCertificateGeneratorStub());
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

    [Fact]
    public async Task GetStatus_ReturnsTheDefaultProviderOnAFreshDataDirectory()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataDir = NewDataDirectory();
        await using var factory = CreateFactory(dataDir);
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync("/v1/secret-storage/status", ct);
        response.EnsureSuccessStatusCode();

        var status = await response.Content.ReadFromJsonAsync<SecretStorageStatusResponse>(ct);
        Assert.Equal("LocalFileKey", status!.CurrentProvider);
    }

    [Fact]
    public async Task GetStatus_WithoutAuth_Returns401()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataDir = NewDataDirectory();
        await using var factory = CreateFactory(dataDir);
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().GetAsync("/v1/secret-storage/status", ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Migrate_FromFileKeyToFileKeyAgain_RotatesTheKeyAndKeepsTheKeyRingReadable()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataDir = NewDataDirectory();
        await using var factory = CreateFactory(dataDir);
        await EnsureDbAsync(factory, ct);

        // Force at least one Data Protection key-ring file to exist before migrating — ASP.NET
        // Data Protection generates its default key lazily on first Protect call, not
        // automatically at host startup.
        string protectedMarker;
        using (var scope = factory.Services.CreateScope())
        {
            var dp = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>();
            protectedMarker = dp.CreateProtector("migration-test").Protect("marker-value");
        }

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsJsonAsync(
            "/v1/secret-storage/migrate", new MigrateSecretStorageRequest("LocalFileKey"), ct);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        using (var scope = factory.Services.CreateScope())
        {
            var dp = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>();
            var recovered = dp.CreateProtector("migration-test").Unprotect(protectedMarker);
            Assert.Equal("marker-value", recovered);
        }
    }

    [Fact]
    public async Task Migrate_ToAnUnknownProvider_ReturnsBadRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataDir = NewDataDirectory();
        await using var factory = CreateFactory(dataDir);
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsJsonAsync(
            "/v1/secret-storage/migrate", new MigrateSecretStorageRequest("NotARealProvider"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private sealed class LocalCertificateGeneratorStub : ICertificateGenerator
    {
        public bool IsInitialized => true;
        public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
        public string GetCaCertificatePem() => "-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----";
        public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => [];
        public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => [];
        public GeneratedCertificate GenerateCa(GenerateCaRequest request) => new();
        public void ImportCa(ImportCaRequest request) { }
        public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];
        public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null) => [];
    }
}
