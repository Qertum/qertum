using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RoleSchemaTests
{
    private static async Task<(SqliteConnection Connection, CertificateRequestDbContext Db)> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        return (connection, db);
    }

    [Fact]
    public async Task CaseVariantDuplicate_IsRejectedByUniqueIndex()
    {
        var ct = TestContext.Current.CancellationToken;
        var (connection, db) = await OpenAsync(ct);
        await using var _c = connection;
        await using var _d = db;
        await db.Database.MigrateAsync(ct);

        db.RolePermissions.Add(new RolePermission { Role = "ops", Permission = AppPermissions.CertificatesView });
        await db.SaveChangesAsync(ct);
        db.RolePermissions.Add(new RolePermission { Role = "OPS", Permission = AppPermissions.CertificatesView });

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task RoleFilter_IgnoresCase()
    {
        var ct = TestContext.Current.CancellationToken;
        var (connection, db) = await OpenAsync(ct);
        await using var _c = connection;
        await using var _d = db;
        await db.Database.MigrateAsync(ct);

        db.RolePermissions.Add(new RolePermission { Role = "operators", Permission = AppPermissions.CertificatesView });
        await db.SaveChangesAsync(ct);
        string[] roles = ["Operators"];

        Assert.Equal(1, await db.RolePermissions.CountAsync(rp => roles.Contains(rp.Role), ct));
        Assert.Equal(1, await db.RolePermissions.CountAsync(rp => rp.Role == "OPERATORS", ct));
    }

    [Fact]
    public async Task ObservedRoles_HasOnlyRoleAndTimestampColumns()
    {
        var ct = TestContext.Current.CancellationToken;
        var (connection, db) = await OpenAsync(ct);
        await using var _c = connection;
        await using var _d = db;
        await db.Database.MigrateAsync(ct);

        var columns = await db.Database
            .SqlQueryRaw<string>("SELECT name AS Value FROM pragma_table_info('ObservedRoles')")
            .ToListAsync(ct);

        Assert.Equal(["FirstSeenUtc", "LastSeenUtc", "Role"], columns.OrderBy(c => c, StringComparer.Ordinal));
    }
}
