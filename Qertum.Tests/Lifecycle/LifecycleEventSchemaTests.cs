using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class LifecycleEventSchemaTests
{
    [Fact]
    public async Task Migrate_CreatesTheTableAndItsSubjectIndex()
    {
        // MigrateAsync also fails when the model has changes no migration contains, so this doubles
        // as the check that the migration captured the entity.
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

        await db.Database.MigrateAsync(ct);

        db.LifecycleEvents.Add(new LifecycleEvent
        {
            Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Audit, OccurredAtUtc = DateTime.UtcNow,
            SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = Guid.NewGuid(),
            Action = "Created", PerformedBy = "alice"
        });
        await db.SaveChangesAsync(ct);

        var indexes = await db.Database
            .SqlQueryRaw<string>("SELECT name AS Value FROM sqlite_master WHERE type = 'index' AND tbl_name = 'LifecycleEvents'")
            .ToListAsync(ct);
        Assert.Contains(indexes, i => i.Contains("SubjectType", StringComparison.Ordinal));
        Assert.Contains(indexes, i => i.Contains("Kind", StringComparison.Ordinal));
    }
}
