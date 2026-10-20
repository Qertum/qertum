using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// A named shared-cache in-memory SQLite database for a test host, where every DbContext opens its
/// own connection from <see cref="ConnectionString"/>.
/// </summary>
/// <remarks>
/// Never register one live <see cref="SqliteConnection"/> for all contexts: the object is not
/// thread-safe, and a background writer running beside the request handlers made it answer
/// "database is locked" (the ACME test flake fixed in bcd7d90). Separate connections get SQLite's own
/// cross-connection locking, which Microsoft.Data.Sqlite waits out. The anchor connection only
/// keeps the database alive — a named in-memory database is dropped when its last connection
/// closes — and is rooted by the DI container through <see cref="ReplaceDbContext"/>.
/// </remarks>
internal sealed class SharedInMemoryDatabase
{
    private readonly SqliteConnection _anchor;

    private SharedInMemoryDatabase(string connectionString, SqliteConnection anchor)
    {
        ConnectionString = connectionString;
        _anchor = anchor;
    }

    public string ConnectionString { get; }

    /// <summary>
    /// With <paramref name="createSchema"/>, also seeds the settings row at PQC stage Off unless
    /// <paramref name="seedSettings"/> is false: the CA default is Enforce, and the suites that use
    /// this issue RSA certificates without being about the stage. Tests that add their own settings
    /// row, or assert there is none, pass <c>seedSettings: false</c>.
    /// </summary>
    public static SharedInMemoryDatabase Create(bool createSchema = false, bool seedSettings = true)
    {
        var connectionString = $"Data Source={Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        var anchor = new SqliteConnection(connectionString);
        anchor.Open();
        var database = new SharedInMemoryDatabase(connectionString, anchor);
        if (createSchema)
        {
            using var context = database.CreateContext();
            context.Database.EnsureCreated();
            if (seedSettings)
            {
                context.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
                context.SaveChanges();
            }
        }
        return database;
    }

    /// <summary>A context on its own connection, for seeding and assertions outside a host.</summary>
    public CertificateRequestDbContext CreateContext() => new(
        new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(ConnectionString).Options,
        new EphemeralDataProtectionProvider());

    /// <summary>
    /// Replaces the host's DbContext registration with one opening a connection per context, and
    /// registers this instance so the container keeps the anchor connection alive.
    /// </summary>
    public void ReplaceDbContext(IServiceCollection services)
    {
        foreach (var descriptor in services
                     .Where(d => d.ServiceType == typeof(DbContextOptions<CertificateRequestDbContext>)
                              || d.ServiceType == typeof(CertificateRequestDbContext))
                     .ToList())
            services.Remove(descriptor);

        services.AddSingleton(this);
        services.AddDbContext<CertificateRequestDbContext>(options => options.UseSqlite(ConnectionString));
    }

    /// <summary>A scope factory whose contexts open their own connections to this database.</summary>
    public IServiceScopeFactory CreateScopeFactory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        ReplaceDbContext(services);
        return services.BuildServiceProvider().GetRequiredService<IServiceScopeFactory>();
    }
}
