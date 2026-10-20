using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Issuers;

/// <summary>
/// The "one default issuer" and "one row per key" rules live in unique indexes, so they hold across
/// processes instead of depending on a check-then-insert.
/// </summary>
public sealed class IssuerModelTests
{
    private static readonly DateTime Now = new(2026, 9, 27, 8, 0, 0, DateTimeKind.Utc);

    internal static Issuer Row(string name, bool isDefault = false, string? spki = null,
        IssuerStatus status = IssuerStatus.Active) => new()
    {
        Name = name,
        Kind = IssuerKind.Root,
        KeyCustody = IssuerKeyCustody.Online,
        Status = status,
        IsDefault = isDefault,
        SpkiSha256 = spki ?? Guid.NewGuid().ToString("N"),
        CreatedAtUtc = Now
    };

    [Fact]
    public async Task TwoDefaultIssuers_AreRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.Issuers.Add(Row("a", isDefault: true));
        await db.SaveChangesAsync(ct);
        db.Issuers.Add(Row("b", isDefault: true));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task ManyNonDefaultIssuers_AreAllowed()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.Issuers.AddRange(Row("a", isDefault: true), Row("b"), Row("c"));
        await db.SaveChangesAsync(ct);

        Assert.Equal(3, await db.Issuers.CountAsync(ct));
    }

    [Fact]
    public async Task SameKeyTwice_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.Issuers.Add(Row("a", spki: "ab"));
        await db.SaveChangesAsync(ct);
        db.Issuers.Add(Row("b", spki: "ab"));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task SameNameTwice_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        db.Issuers.Add(Row("same"));
        await db.SaveChangesAsync(ct);
        db.Issuers.Add(Row("same"));

        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task EnumsAndIssuerIdRoundTrip_AsNamesAndGuid()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        var parent = Row("root");
        var child = Row("child", status: IssuerStatus.PendingCertificate);
        child.Kind = IssuerKind.Intermediate;
        child.ParentIssuerId = parent.Id;
        await using (var db = database.CreateContext())
        {
            db.Issuers.AddRange(parent, child);
            await db.SaveChangesAsync(ct);
        }

        await using var check = database.CreateContext();
        var status = await check.Database
            .SqlQueryRaw<string>("SELECT \"Status\" AS \"Value\" FROM \"Issuers\" WHERE \"Name\" = 'child'")
            .SingleAsync(ct);
        Assert.Equal("PendingCertificate", status);
        var loaded = await check.Issuers.SingleAsync(i => i.Name == "child", ct);
        Assert.Equal(parent.Id, loaded.ParentIssuerId);
        Assert.Equal(IssuerKind.Intermediate, loaded.Kind);
    }

    [Fact]
    public async Task CertificateRequestAndTemplate_CarryAnOptionalIssuerId()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        var issuer = Row("root");
        await using (var db = database.CreateContext())
        {
            db.Issuers.Add(issuer);
            db.CertificateRequests.Add(new CertificateRequest { CommonName = "x", RequestedBy = "t", IssuerId = issuer.Id });
            db.CertificateRequests.Add(new CertificateRequest { CommonName = "y", RequestedBy = "t" });
            db.CertificateTemplates.Add(new CertificateTemplate { Name = "T", TypeKey = "T1", IssuerId = issuer.Id });
            await db.SaveChangesAsync(ct);
        }

        await using var check = database.CreateContext();
        Assert.Equal(issuer.Id, (await check.CertificateRequests.SingleAsync(r => r.CommonName == "x", ct)).IssuerId);
        Assert.Null((await check.CertificateRequests.SingleAsync(r => r.CommonName == "y", ct)).IssuerId);
        Assert.Equal(issuer.Id, (await check.CertificateTemplates.SingleAsync(t => t.TypeKey == "T1", ct)).IssuerId);
    }

    [Fact]
    public void IssuerId_SerializesAsAPlainGuidString()
    {
        var id = new IssuerId(Guid.Parse("11111111-2222-3333-4444-555555555555"));
        Assert.Equal("\"11111111-2222-3333-4444-555555555555\"", System.Text.Json.JsonSerializer.Serialize(id));
        Assert.Equal(id, System.Text.Json.JsonSerializer.Deserialize<IssuerId>("\"11111111-2222-3333-4444-555555555555\""));
    }
}
