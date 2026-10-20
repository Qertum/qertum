using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkOperationModelTests
{
    private static async Task<(SqliteConnection Connection, CertificateRequestDbContext Db)> OpenAsync(CancellationToken ct)
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync(ct);
        var db = new CertificateRequestDbContext(
            new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite(connection).Options,
            new EphemeralDataProtectionProvider());
        await db.Database.EnsureCreatedAsync(ct);
        return (connection, db);
    }

    [Fact]
    public async Task OperationAndItems_RoundTrip_WithNamesStoredForEnums()
    {
        var ct = TestContext.Current.CancellationToken;
        var (connection, db) = await OpenAsync(ct);
        await using var _ = connection;
        await using var __ = db;

        var requestId = new CertificateRequestId(Guid.NewGuid());
        var operation = new BulkOperation
        {
            Kind = BulkOperationKind.Revoke,
            Status = BulkOperationStatus.Previewed,
            FilterJson = "{\"all\":true}",
            Reason = "key compromise",
            CreatedBy = "alice",
            CreatedBySubject = "sub-alice",
            CreatedAtUtc = new DateTime(2026, 10, 8, 12, 0, 0, DateTimeKind.Utc),
            ItemCount = 1
        };
        db.BulkOperations.Add(operation);
        db.BulkOperationItems.Add(new BulkOperationItem { OperationId = operation.Id, RequestId = requestId });
        await db.SaveChangesAsync(ct);

        var kind = await db.Database.SqlQueryRaw<string>("SELECT \"Kind\" AS \"Value\" FROM \"BulkOperations\"").SingleAsync(ct);
        Assert.Equal("Revoke", kind);

        db.ChangeTracker.Clear();
        var item = await db.BulkOperationItems.SingleAsync(ct);
        Assert.Equal(requestId, item.RequestId);
        Assert.Equal(BulkItemOutcome.Pending, item.Outcome);
    }

    [Fact]
    public async Task Item_CompositeKey_RefusesTheSameRequestTwiceInOneOperation()
    {
        var ct = TestContext.Current.CancellationToken;
        var (connection, db) = await OpenAsync(ct);
        await using var _ = connection;
        await using var __ = db;

        var operation = new BulkOperation { Kind = BulkOperationKind.Renew, CreatedBy = "a", CreatedAtUtc = DateTime.UtcNow };
        var requestId = new CertificateRequestId(Guid.NewGuid());
        db.BulkOperations.Add(operation);
        db.BulkOperationItems.Add(new BulkOperationItem { OperationId = operation.Id, RequestId = requestId });
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();

        db.BulkOperationItems.Add(new BulkOperationItem { OperationId = operation.Id, RequestId = requestId });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public void BulkOperationCompleted_BelongsToItsOwnFamily_AndCarriesNoCertificateFields()
    {
        Assert.Equal(WebhookEventFamily.BulkOperation, WellKnownWebhookEvents.FamilyOf("BulkOperationCompleted"));
        var fields = WebhookEventFields.For(WebhookEventFamily.BulkOperation);
        Assert.Contains("operationId", fields);
        Assert.DoesNotContain("commonName", fields);
    }
}
