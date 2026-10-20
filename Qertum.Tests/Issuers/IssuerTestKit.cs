using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// A temp CaData directory, a shared in-memory DB, one Data Protection provider and a registry over
/// them — the pieces every issuer test needs, wired the way AddCustomCaServices wires them.
/// </summary>
internal sealed class IssuerTestKit : IDisposable
{
    public string CaDataDirectory { get; } = Path.Combine(Path.GetTempPath(), "IssuerKit-" + Guid.NewGuid().ToString("N"));
    public IDataProtectionProvider DataProtection { get; } = new EphemeralDataProtectionProvider();
    public SharedInMemoryDatabase Database { get; }
    public IDistributedCache Cache { get; } = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
    public IssuerStorage Storage { get; }
    public CertificateGenerator Legacy { get; }
    public IServiceScopeFactory Scopes { get; }

    /// <param name="createSchema">
    /// False for a kit handed to an ApiService host: the host applies the schema itself with
    /// Migrate(), which fails on a database EnsureCreated already filled.
    /// </param>
    public IssuerTestKit(bool createSchema = true)
    {
        Database = SharedInMemoryDatabase.Create(createSchema);
        Directory.CreateDirectory(CaDataDirectory);
        Storage = new IssuerStorage(new CaDataOptions { Directory = CaDataDirectory });
        Legacy = NewGenerator(new CaDataOptions { Directory = CaDataDirectory });
        Scopes = Database.CreateScopeFactory();
    }

    public CertificateGenerator NewGenerator(CaDataOptions options) =>
        new(DataProtection, options, NullLogger<CertificateGenerator>.Instance);

    public IssuerRegistry NewRegistry(ICertificateGenerator? legacy = null, TimeProvider? time = null) =>
        new(Scopes, legacy ?? Legacy, Storage, DataProtection, Cache, NullLoggerFactory.Instance, time);

    /// <summary>Initializes the legacy files (the pre-hierarchy CA).</summary>
    public void InitializeLegacy(string cn = "Legacy Root", CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.Rsa) =>
        Legacy.GenerateCa(new GenerateCaRequest { CommonName = cn, KeyAlgorithm = algorithm, ValidityDays = 3650 });

    /// <summary>Creates a self-signed online root in its own issuer directory and inserts its row.</summary>
    public async Task<Issuer> AddOnlineRootAsync(string name, bool isDefault = false,
        CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.Rsa, IssuerStatus status = IssuerStatus.Active)
    {
        var issuer = new Issuer
        {
            Name = name, Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
            Status = status, IsDefault = isDefault, CreatedAtUtc = DateTime.UtcNow
        };
        var generator = NewGenerator(Storage.OptionsFor(issuer));
        generator.GenerateCa(new GenerateCaRequest { CommonName = name, KeyAlgorithm = algorithm, ValidityDays = 3650 });
        issuer.CertificatePem = generator.GetCaCertificatePem();
        IssuerCertificateFacts.Read(issuer.CertificatePem).ApplyTo(issuer);
        await using var db = Database.CreateContext();
        db.Issuers.Add(issuer);
        await db.SaveChangesAsync();
        return issuer;
    }

    public void Dispose()
    {
        if (Directory.Exists(CaDataDirectory)) try { Directory.Delete(CaDataDirectory, true); } catch { /* best effort */ }
    }
}
