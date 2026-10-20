using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class IssuancePolicySchemaTests
{
    [Fact]
    public async Task Migrate_FreshDatabase_CreatesPolicyTablesAndLeavesSeededTemplatesUnlinked()
    {
        // MigrateAsync also fails if the model has changes the migrations do not contain, so this
        // doubles as a check that the migration captured the whole model.
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());

        await db.Database.MigrateAsync(ct);

        Assert.Equal(0, await db.IssuancePolicies.CountAsync(ct));
        Assert.Equal(0, await db.IssuancePolicyVersions.CountAsync(ct));
        Assert.Equal(5, await db.CertificateTemplates.CountAsync(ct));
        Assert.True(await db.CertificateTemplates.AllAsync(t => t.IssuancePolicyId == null, ct));
    }

    [Fact]
    public async Task SecondDraftForSamePolicy_IsRejectedByFilteredUniqueIndex()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var policy = new IssuancePolicy { Name = "two-drafts" };
        scope.Db.IssuancePolicies.Add(policy);
        scope.Db.IssuancePolicyVersions.Add(NewVersion(policy.Id, 1, IssuancePolicyVersionStatus.Draft));
        await scope.Db.SaveChangesAsync(ct);

        scope.Db.IssuancePolicyVersions.Add(NewVersion(policy.Id, 2, IssuancePolicyVersionStatus.Draft));

        await Assert.ThrowsAsync<DbUpdateException>(() => scope.Db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task DraftPublishedAndSupersededForSamePolicy_CanCoexist()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var policy = new IssuancePolicy { Name = "coexist" };
        scope.Db.IssuancePolicies.Add(policy);
        scope.Db.IssuancePolicyVersions.AddRange(
            NewVersion(policy.Id, 1, IssuancePolicyVersionStatus.Superseded),
            NewVersion(policy.Id, 2, IssuancePolicyVersionStatus.Published),
            NewVersion(policy.Id, 3, IssuancePolicyVersionStatus.Draft));

        await scope.Db.SaveChangesAsync(ct);

        Assert.Equal(3, await scope.Db.IssuancePolicyVersions.CountAsync(v => v.PolicyId == policy.Id, ct));
    }

    private static IssuancePolicyVersion NewVersion(IssuancePolicyId policyId, int number, IssuancePolicyVersionStatus status) =>
        new() { PolicyId = policyId, VersionNumber = number, Status = status, CreatedBy = "test" };
}
