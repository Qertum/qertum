using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Issuers;
using Qertum.Services.Recovery;

namespace Qertum.Tests.Recovery;

/// <summary>
/// A real on-disk data directory built the way the hosts build it (<c>AddCustomCaServices</c>): migrated database,
/// key ring, legacy root CA, one issued and one revoked certificate. <see cref="ReopenAsync"/> damages the
/// directory and rebuilds the services, which is what restoring a bad backup looks like.
/// </summary>
internal sealed class RestoreUsabilityHost : IAsyncDisposable
{
    public string DataDirectory { get; }
    private ServiceProvider _provider;

    private RestoreUsabilityHost(string directory)
    {
        DataDirectory = directory;
        _provider = Build(directory);
    }

    private static ServiceProvider Build(string directory)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        // Hosts register the shared cache themselves; the check caches nothing, so a private in-memory one serves.
        services.AddDistributedMemoryCache();
        services.AddCustomCaServices($"Data Source={Path.Combine(directory, "certificate-requests.db")}");
        services.AddScoped<RestoreUsabilityChecker>();
        return services.BuildServiceProvider();
    }

    public static async Task<RestoreUsabilityHost> CreateAsync(bool withCa = true)
    {
        var directory = Path.Combine(Path.GetTempPath(), "restore-usability-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var host = new RestoreUsabilityHost(directory);
        await host.SeedAsync(withCa);
        return host;
    }

    private async Task SeedAsync(bool withCa)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = _provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.MigrateAsync(ct);
        if (!withCa)
            return;

        var generator = scope.ServiceProvider.GetRequiredService<ICertificateGenerator>();
        generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "Restore Check Root", KeyAlgorithm = CertificateKeyAlgorithm.Rsa, ValidityDays = 365
        });
        await IssuerBootstrap.EnsureLegacyIssuerAsync(db, generator, null, TimeProvider.System, ct);

        var settings = new CaSettings { Id = 1, PqcStage = PqcStage.Off };
        db.Settings.Add(settings);
        var now = DateTime.UtcNow;
        var good = generator.GenerateCertificate(new CertificateRequest { CommonName = "leaf.restore.test", Type = "WebServer" }, settings);
        var revoked = generator.GenerateCertificate(new CertificateRequest { CommonName = "revoked.restore.test", Type = "WebServer" }, settings);
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "leaf.restore.test", RequestedBy = "alice", Type = "WebServer", Status = CertificateRequestStatus.Issued,
            CertificatePem = good.CertificatePem, PrivateKeyPem = good.PrivateKeyPem, SerialNumber = good.SerialNumber,
            ValidFrom = now.AddDays(-1), ValidTo = now.AddDays(300)
        });
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "revoked.restore.test", RequestedBy = "alice", Type = "WebServer", Status = CertificateRequestStatus.Revoked,
            CertificatePem = revoked.CertificatePem, PrivateKeyPem = revoked.PrivateKeyPem, SerialNumber = revoked.SerialNumber,
            ValidFrom = now.AddDays(-1), ValidTo = now.AddDays(300), RevokedAtUtc = now, RevocationReason = "keyCompromise"
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<RestoreUsabilityReport> RunAsync()
    {
        await using var scope = _provider.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RestoreUsabilityChecker>().RunAsync(TestContext.Current.CancellationToken);
    }

    public async Task ExecuteSqlAsync(string sql)
    {
        await using var scope = _provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.ExecuteSqlRawAsync(sql, TestContext.Current.CancellationToken);
    }

    /// <summary>Runs <paramref name="damage"/> on the data directory with no services holding it, then rebuilds the services.</summary>
    public async Task ReopenAsync(Action<string> damage)
    {
        await _provider.DisposeAsync();
        SqliteConnection.ClearAllPools();
        damage(DataDirectory);
        _provider = Build(DataDirectory);
    }

    public async ValueTask DisposeAsync()
    {
        await _provider.DisposeAsync();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(DataDirectory, recursive: true); } catch { /* best effort */ }
    }
}
