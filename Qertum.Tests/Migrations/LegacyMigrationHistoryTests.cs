using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Qertum.Services;

namespace Qertum.Tests.Migrations;

/// <summary>
/// Databases created by released images list their applied migrations in <c>__EFMigrationsHistory</c>. The
/// migration set was later flattened into one baseline that keeps the id of the first migration, so such a
/// database must be recognised as up to date instead of having its tables created a second time.
/// </summary>
public sealed class LegacyMigrationHistoryTests
{
    private static readonly string[] ReleasedMigrationIds =
    [
        "20261014001315_InitialCreate",
        "20261017223704_AddApprovals",
        "20261017232658_ApprovalOpenRequestIndex",
    ];

    private static CertificateRequestDbContext NewContext(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

    [Fact]
    public async Task DatabaseWithTheReleasedMigrationHistory_UpgradesInPlace_ApplyingOnlyLaterMigrations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        await using (var creating = NewContext(connection))
        {
            // The schema the alpha images shipped: the baseline only, none of the migrations added since.
            await creating.GetService<IMigrator>().MigrateAsync(ReleasedMigrationIds[0], ct);
            creating.RolePermissions.Add(new RolePermission { Role = "keep-me", Permission = AppPermissions.CertificatesView });
            await creating.SaveChangesAsync(ct);
        }

        // What a database made by an alpha image looks like: the same schema, with every released migration recorded.
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "DELETE FROM \"__EFMigrationsHistory\";" + string.Concat(ReleasedMigrationIds.Select(id =>
                $"INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ('{id}', '10.0.0');"));
            await command.ExecuteNonQueryAsync(ct);
        }

        await using var upgrading = NewContext(connection);
        Assert.Equal(["20261022163742_AddIssuerStrength", "20261027173855_AddRevokedIssuerMode"], await upgrading.Database.GetPendingMigrationsAsync(ct));
        await upgrading.Database.MigrateAsync(ct);

        Assert.Equal("keep-me", (await upgrading.RolePermissions.SingleAsync(ct)).Role);
    }
}
