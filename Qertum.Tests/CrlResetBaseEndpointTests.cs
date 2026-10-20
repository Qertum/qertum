using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// HTTP-level tests for <c>POST /v1/crl/reset-base</c> — an admin action that forces a fresh full
/// CRL and delta base on demand, rather than waiting for the next <c>/crl</c> fetch to do it as a
/// side effect. The scheduled CrlRefresh job keeps the base fresh on its own; this is the manual override.
/// </summary>
public sealed class CrlResetBaseEndpointTests : IDisposable
{
    private readonly string _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
    private readonly CertificateGenerator _generator;

    public CrlResetBaseEndpointTests()
    {
        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "Crl Reset Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task ResetBase_WithoutAuth_Returns401()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().PostAsync("/v1/crl/reset-base", null, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ResetBase_PublishesANewBaseAndEvictsTheCachedDelta()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        // Seed a stale cached full CRL and a delta computed against it — a reset must overwrite the
        // former and drop the latter, exactly like a fresh /crl fetch already does.
        var cache = factory.Services.GetRequiredService<IDistributedCache>();
        await cache.SetAsync(CrlCache.Key, [9, 9, 9], ct);
        await cache.SetAsync(CrlCache.DeltaKey, [8, 8, 8], ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.PostAsync("/v1/crl/reset-base", null, ct);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<CrlBaseResetResponse>(ct);
        Assert.NotNull(result);
        Assert.True(result!.CrlNumber > 0);

        Assert.Null(await cache.GetAsync(CrlCache.DeltaKey, ct));
        var cachedCrl = await cache.GetAsync(CrlCache.Key, ct);
        Assert.NotNull(cachedCrl);
        Assert.NotEqual(new byte[] { 9, 9, 9 }, cachedCrl);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var settings = await db.Settings.SingleAsync(s => s.Id == 1, ct);
        Assert.Equal(result.CrlNumber, settings.BaseCrlNumber);
    }

    [Fact]
    public async Task ResetBase_EachCallClaimsAFreshCrlNumber()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var first = await (await client.PostAsync("/v1/crl/reset-base", null, ct))
            .Content.ReadFromJsonAsync<CrlBaseResetResponse>(ct);
        var second = await (await client.PostAsync("/v1/crl/reset-base", null, ct))
            .Content.ReadFromJsonAsync<CrlBaseResetResponse>(ct);

        Assert.True(second!.CrlNumber > first!.CrlNumber);
    }

    private WebApplicationFactory<ApiServiceProgram> CreateFactory()
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
                }).AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

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
}
