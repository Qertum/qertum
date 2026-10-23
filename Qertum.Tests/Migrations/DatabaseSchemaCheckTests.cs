using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Migrations;

public sealed class DatabaseSchemaCheckTests
{
    [Fact]
    public async Task MissingTables_IsEmptyAfterMigrate_AndNamesATableThatIsGone()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.MigrateAsync(ct);

        Assert.Empty(DatabaseSchemaCheck.MissingTables(db));

        // A database from an older build: the history says "up to date", the approvals table does not exist.
        await db.Database.ExecuteSqlRawAsync("DROP TABLE \"ApprovalRequests\"", ct);

        Assert.Equal(["ApprovalRequests"], DatabaseSchemaCheck.MissingTables(db));
    }
}
