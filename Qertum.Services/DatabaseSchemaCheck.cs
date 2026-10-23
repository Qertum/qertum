using Microsoft.EntityFrameworkCore;

namespace Qertum.Services;

/// <summary>
/// Compares the tables the model maps with the tables the SQLite database holds. <c>Migrate()</c> trusts the
/// migration history, so a database whose history names a migration id that was later rewritten (the baseline
/// keeps the id of the first alpha migration) counts as up to date while tables are missing.
/// </summary>
public static class DatabaseSchemaCheck
{
    /// <summary>Names of the model's tables that the database does not have, in model order.</summary>
    public static IReadOnlyList<string> MissingTables(DbContext db)
    {
        var existing = db.Database
            .SqlQueryRaw<string>("SELECT name AS Value FROM sqlite_master WHERE type = 'table'")
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return db.Model.GetEntityTypes()
            .Where(e => e.GetViewName() is null)
            .Select(e => e.GetTableName())
            .OfType<string>()
            .Distinct()
            .Where(table => !existing.Contains(table))
            .ToList();
    }
}
