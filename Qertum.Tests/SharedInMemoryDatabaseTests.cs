using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// The helper every web test host uses for its database. Each DbContext must get its own connection,
/// because background writers (the ACME challenge verifier, the lifecycle event sink) use the
/// database concurrently with request handlers, and one SqliteConnection object is not thread-safe.
/// </summary>
public sealed class SharedInMemoryDatabaseTests
{
    [Fact]
    public async Task ContextsFromDifferentScopes_UseDifferentConnectionsToTheSameDatabase()
    {
        var ct = TestContext.Current.CancellationToken;
        using var provider = BuildProvider(SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false));

        using var first = provider.CreateScope();
        using var second = provider.CreateScope();
        var a = first.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var b = second.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();

        Assert.NotSame(a.Database.GetDbConnection(), b.Database.GetDbConnection());
        a.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, Id = 1 });
        await a.SaveChangesAsync(ct);
        Assert.True(await b.Settings.AnyAsync(ct));
    }

    [Fact]
    public async Task TheDatabaseOutlivesAGarbageCollection()
    {
        // The anchor connection is what keeps a named in-memory database alive. When nothing
        // referenced it, a collection closed its handle and dropped every table mid-run.
        var ct = TestContext.Current.CancellationToken;
        using var provider = BuildProvider(SharedInMemoryDatabase.Create(createSchema: true));

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        Assert.Equal(0, await db.CertificateRequests.CountAsync(ct));
    }

    private static ServiceProvider BuildProvider(SharedInMemoryDatabase database)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IDataProtectionProvider, EphemeralDataProtectionProvider>();
        database.ReplaceDbContext(services);
        return services.BuildServiceProvider();
    }
}
