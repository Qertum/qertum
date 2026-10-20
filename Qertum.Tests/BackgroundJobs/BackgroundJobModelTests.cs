using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.BackgroundJobs;

/// <summary>
/// The queue's one-active-job-per-key rule lives in a filtered unique index, so it holds across
/// processes and races rather than depending on a check-then-insert.
/// </summary>
public sealed class BackgroundJobModelTests
{
    private static readonly DateTime Now = new(2026, 9, 25, 8, 0, 0, DateTimeKind.Utc);

    private static BackgroundJob Job(string? key, BackgroundJobStatus status = BackgroundJobStatus.Pending) => new()
    {
        JobType = WellKnownJobTypes.CrlRefresh,
        ConcurrencyKey = key,
        Status = status,
        RequestedBy = "test",
        RequestedAtUtc = Now,
        NextAttemptAfterUtc = Now
    };

    [Fact]
    public async Task TwoActiveJobs_WithTheSameKey_AreRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.BackgroundJobs.Add(Job("crl-refresh"));
        await db.SaveChangesAsync(ct);
        db.BackgroundJobs.Add(Job("crl-refresh", BackgroundJobStatus.Processing));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task FinishedJobs_DoNotHoldTheKey_AndNullKeysNeverConflict()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.BackgroundJobs.AddRange(
            Job("crl-refresh", BackgroundJobStatus.Completed),
            Job("crl-refresh", BackgroundJobStatus.Failed),
            Job("crl-refresh"),
            Job(null),
            Job(null));
        await db.SaveChangesAsync(ct);

        Assert.Equal(5, await db.BackgroundJobs.CountAsync(ct));
    }

    [Fact]
    public async Task Status_IsStoredAsItsName()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using (var db = database.CreateContext())
        {
            db.BackgroundJobs.Add(Job("k", BackgroundJobStatus.Processing));
            await db.SaveChangesAsync(ct);
        }

        await using var check = database.CreateContext();
        var stored = await check.Database
            .SqlQueryRaw<string>("SELECT \"Status\" AS \"Value\" FROM \"BackgroundJobs\"")
            .SingleAsync(ct);
        Assert.Equal("Processing", stored);
    }

    [Fact]
    public void BackgroundJobId_SerializesAsAPlainGuidString()
    {
        var id = new BackgroundJobId(Guid.Parse("7d0b3c1e-2f7a-4a52-9b8e-0f5a1d2c3b4a"));
        Assert.Equal("\"7d0b3c1e-2f7a-4a52-9b8e-0f5a1d2c3b4a\"", JsonSerializer.Serialize(id));
        Assert.Equal(id, JsonSerializer.Deserialize<BackgroundJobId>("\"7d0b3c1e-2f7a-4a52-9b8e-0f5a1d2c3b4a\""));
    }
}
