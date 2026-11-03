using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Qertum.Services;

namespace Qertum.Tests.Migrations;

/// <summary>
/// The schema is frozen at the baseline the alpha images shipped; every later migration must upgrade a database
/// that already holds data. The test walks the migrations after the baseline one at a time, so a new migration
/// is covered without editing it, and it fails when a migration loses a row or leaves a model table missing.
/// </summary>
public sealed class MigrationUpgradePathTests
{
    private const string Baseline = "20261014001315_InitialCreate";

    private static CertificateRequestDbContext NewContext(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

    private static async Task<long> CountAsync(SqliteConnection connection, string table, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
        return (long)(await command.ExecuteScalarAsync(ct))!;
    }

    [Fact]
    public async Task EveryMigrationAfterTheBaseline_UpgradesADatabaseHoldingData_WithoutLosingRows()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);

        await using var db = NewContext(connection);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync(Baseline, ct);

        // Rows as an alpha image holds them: the settings singleton, filled column by column from the schema so a
        // NOT NULL column without a default cannot make the seed depend on this test knowing it.
        await using (var seed = connection.CreateCommand())
        {
            seed.CommandText = "SELECT name, type FROM pragma_table_info('Settings') WHERE \"notnull\" = 1 AND dflt_value IS NULL";
            var columns = new List<(string Name, string Type)>();
            await using (var reader = await seed.ExecuteReaderAsync(ct))
                while (await reader.ReadAsync(ct)) columns.Add((reader.GetString(0), reader.GetString(1)));
            var names = string.Join(",", columns.Select(c => $"\"{c.Name}\""));
            var values = string.Join(",", columns.Select(c => c.Name == "Id" ? "1" : c.Type.Contains("INT", StringComparison.OrdinalIgnoreCase) ? "0" : "''"));
            seed.CommandText = $"INSERT INTO \"Settings\" ({names}) VALUES ({values})";
            await seed.ExecuteNonQueryAsync(ct);
        }
        db.RolePermissions.Add(new RolePermission { Role = "keep-me", Permission = AppPermissions.CertificatesView });
        await db.SaveChangesAsync(ct);
        // A published policy version, for the rule columns later migrations add (AddEmailUpnPolicyRules).
        const string policyId = "8f0c4f5e-0000-4000-8000-000000000001";
        await InsertMinimalAsync(connection, "IssuancePolicies", new() { ["Id"] = $"'{policyId}'", ["Name"] = "'keep-policy'" }, ct);
        await InsertMinimalAsync(connection, "IssuancePolicyVersions",
            new() { ["Id"] = "'8f0c4f5e-0000-4000-8000-000000000002'", ["PolicyId"] = $"'{policyId}'", ["Status"] = "'Published'", ["VersionNumber"] = "1" }, ct);

        var later = db.Database.GetMigrations().SkipWhile(id => id != Baseline).Skip(1).ToList();
        foreach (var id in later)
        {
            await migrator.MigrateAsync(id, ct);
            Assert.Equal(1, await CountAsync(connection, "Settings", ct));
            Assert.Equal(1, await CountAsync(connection, "RolePermissions", ct));
        }

        Assert.Empty(await db.Database.GetPendingMigrationsAsync(ct));
        Assert.Empty(DatabaseSchemaCheck.MissingTables(db));

        // A migration that adds a column to existing rows back-fills it; AddIssuerStrength back-fills Warn.
        await using var read = connection.CreateCommand();
        read.CommandText = "SELECT \"IssuerStrengthMode\" FROM \"Settings\" WHERE \"Id\" = 1";
        Assert.Equal("Warn", (string)(await read.ExecuteScalarAsync(ct))!);

        // AddRevokedIssuerMode back-fills HardStop and adds the nullable Issuers.RevokedAtUtc.
        await using var readMode = connection.CreateCommand();
        readMode.CommandText = "SELECT \"RevokedIssuerMode\" FROM \"Settings\" WHERE \"Id\" = 1";
        Assert.Equal("HardStop", (string)(await readMode.ExecuteScalarAsync(ct))!);
        await using var readColumn = connection.CreateCommand();
        readColumn.CommandText = "SELECT COUNT(*) FROM pragma_table_info('Issuers') WHERE name = 'RevokedAtUtc'";
        Assert.Equal(1L, (long)(await readColumn.ExecuteScalarAsync(ct))!);

        // AddEmailUpnPolicyRules back-fills "[]" (unrestricted), so a published policy keeps issuing as before.
        await using var readRules = connection.CreateCommand();
        readRules.CommandText = "SELECT \"AllowedEmailDomainsJson\" || '|' || \"AllowedUpnSuffixesJson\" FROM \"IssuancePolicyVersions\"";
        Assert.Equal("[]|[]", (string)(await readRules.ExecuteScalarAsync(ct))!);
        Assert.Equal(1, await CountAsync(connection, "IssuancePolicyVersions", ct));
    }

    /// <summary>Inserts a row giving every NOT NULL column without a default a placeholder, then the named values.</summary>
    private static async Task InsertMinimalAsync(SqliteConnection connection, string table, Dictionary<string, string> values, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT name, type FROM pragma_table_info('{table}') WHERE \"notnull\" = 1 AND dflt_value IS NULL";
        var columns = new Dictionary<string, string>(values);
        await using (var reader = await command.ExecuteReaderAsync(ct))
            while (await reader.ReadAsync(ct))
                columns.TryAdd(reader.GetString(0), reader.GetString(1).Contains("INT", StringComparison.OrdinalIgnoreCase) ? "0" : "''");
        command.CommandText = $"INSERT INTO \"{table}\" ({string.Join(",", columns.Keys.Select(k => $"\"{k}\""))}) VALUES ({string.Join(",", columns.Values)})";
        await command.ExecuteNonQueryAsync(ct);
    }
}
