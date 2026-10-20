using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcSchemaTests
{
    [Fact]
    public async Task NewSettingsRow_DefaultsToEnforce_AndStageRoundTripsAsAName()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        await using (var db = database.CreateContext())
        {
            db.Settings.Add(new CaSettings { Id = 1 });
            await db.SaveChangesAsync(ct);
        }

        await using var read = database.CreateContext();
        Assert.Equal(PqcStage.Enforce, (await read.Settings.SingleAsync(ct)).PqcStage);
        var raw = await read.Database.SqlQueryRaw<string>("SELECT PqcStage AS Value FROM Settings").SingleAsync(ct);
        Assert.Equal("Enforce", raw);
    }

    [Fact]
    public async Task ExplicitOff_IsStoredAsOff_NotReplacedByTheColumnDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        await using (var db = database.CreateContext())
        {
            db.Settings.Add(new CaSettings { Id = 1, PqcStage = PqcStage.Off });
            await db.SaveChangesAsync(ct);
        }

        await using var read = database.CreateContext();
        Assert.Equal(PqcStage.Off, (await read.Settings.SingleAsync(ct)).PqcStage);
    }

    [Fact]
    public async Task TemplateOverride_IsNullByDefault_AndPersists()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        await using var db = database.CreateContext();
        var template = await db.CertificateTemplates.FirstAsync(t => t.TypeKey == "WebServer", ct);
        Assert.Null(template.PqcStageOverride);

        template.PqcStageOverride = PqcStage.Warn;
        await db.SaveChangesAsync(ct);

        await using var read = database.CreateContext();
        Assert.Equal(PqcStage.Warn,
            (await read.CertificateTemplates.FirstAsync(t => t.TypeKey == "WebServer", ct)).PqcStageOverride);
    }

    [Fact]
    public async Task PqcException_RoundTrips()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        var id = new PqcExceptionId(Guid.NewGuid());
        await using (var db = database.CreateContext())
        {
            db.PqcExceptions.Add(new PqcException
            {
                Id = id, TemplateTypeKey = "WebServer", NamePattern = "legacy.corp.example",
                Family = PqcExceptionFamily.Rsa, ExpiresAtUtc = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                Reason = "old load balancer", GrantedBy = "alice", CreatedAtUtc = new DateTime(2026, 9, 29, 0, 0, 0, DateTimeKind.Utc)
            });
            await db.SaveChangesAsync(ct);
        }

        await using var read = database.CreateContext();
        var stored = await read.PqcExceptions.SingleAsync(e => e.Id == id, ct);
        Assert.Equal(PqcExceptionFamily.Rsa, stored.Family);
        Assert.Equal("old load balancer", stored.Reason);
    }
}
