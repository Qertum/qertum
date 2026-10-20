using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class KeyCustodyApiTests
{
    private const string Author = "author";

    [Fact]
    public async Task DraftSave_RoundTripsKeyCustody_AndPublishCarriesIt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await service.CreateAsync(new SaveIssuancePolicyRequest { Name = "custody" }, Author, ct);

        var saved = (await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest
        {
            KeyCustody = KeyCustodyMode.RequireClientGenerated
        }, Author, ct))!;

        Assert.Equal(KeyCustodyMode.RequireClientGenerated, saved.Draft!.KeyCustody);

        var published = (await service.PublishAsync(created.Id, new PublishIssuancePolicyRequest
        {
            DraftVersionId = saved.Draft.Id,
            DraftUpdatedAtUtc = saved.Draft.UpdatedAtUtc
        }, "publisher", ct))!;

        Assert.Equal(KeyCustodyMode.RequireClientGenerated, published.Published!.KeyCustody);
    }

    [Fact]
    public async Task DraftSave_OmittingKeyCustody_LeavesThePolicyUnrestricted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await service.CreateAsync(new SaveIssuancePolicyRequest { Name = "default" }, Author, ct);

        var saved = (await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest(), Author, ct))!;

        Assert.Equal(KeyCustodyMode.Any, saved.Draft!.KeyCustody);
    }

    [Fact]
    public async Task KeyCustody_IsStoredAsItsName()
    {
        // The column carries the enum name, like Status, so a hand-inspected database reads
        // plainly.
        var ct = TestContext.Current.CancellationToken;
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        await using var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new Microsoft.AspNetCore.DataProtection.EphemeralDataProtectionProvider());
        await db.Database.MigrateAsync(ct);

        var policy = new IssuancePolicy { Name = "stored" };
        db.IssuancePolicies.Add(policy);
        db.IssuancePolicyVersions.Add(new IssuancePolicyVersion
        {
            PolicyId = policy.Id,
            VersionNumber = 1,
            Status = IssuancePolicyVersionStatus.Published,
            KeyCustody = KeyCustodyMode.RequireClientGenerated,
            CreatedBy = "test"
        });
        await db.SaveChangesAsync(ct);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT \"KeyCustody\" FROM \"IssuancePolicyVersions\"";
        Assert.Equal("RequireClientGenerated", (string?)await command.ExecuteScalarAsync(ct));
    }
}
