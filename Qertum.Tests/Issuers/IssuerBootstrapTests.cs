using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// Upgrade path: a single-root deployment becomes issuer #1 with no behaviour change. The row is
/// derived from the files on disk, so it is inserted by code rather than by the migration.
/// </summary>
public sealed class IssuerBootstrapTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "IssuerBootstrap-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }

    private CertificateGenerator Legacy(bool initialize = true)
    {
        var generator = new CertificateGenerator(new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _dir }, NullLogger<CertificateGenerator>.Instance);
        if (initialize)
            generator.GenerateCa(new GenerateCaRequest { CommonName = "Legacy Root", ValidityDays = 365 });
        return generator;
    }

    [Fact]
    public async Task Bootstrap_WithoutCaFiles_DoesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        var result = await IssuerBootstrap.EnsureLegacyIssuerAsync(db, Legacy(initialize: false), null, TimeProvider.System, ct);

        Assert.Null(result);
        Assert.Equal(0, await db.Issuers.CountAsync(ct));
    }

    [Fact]
    public async Task Bootstrap_RegistersTheLegacyCaAsActiveOnlineDefaultRoot()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var legacy = Legacy();

        var issuer = await IssuerBootstrap.EnsureLegacyIssuerAsync(db, legacy, null, TimeProvider.System, ct);

        Assert.NotNull(issuer);
        Assert.Equal(IssuerKind.Root, issuer.Kind);
        Assert.Equal(IssuerKeyCustody.Online, issuer.KeyCustody);
        Assert.Equal(IssuerStatus.Active, issuer.Status);
        Assert.True(issuer.IsDefault);
        Assert.True(issuer.LegacyFiles);
        Assert.Equal(legacy.GetCaCertificatePem().Trim(), issuer.CertificatePem!.Trim());
        Assert.Equal(IssuerBootstrap.LegacyIdFor(issuer.SpkiSha256), issuer.Id);
    }

    [Fact]
    public async Task Bootstrap_BackFillsIssuedRowsOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        db.CertificateRequests.AddRange(
            new CertificateRequest { CommonName = "issued", RequestedBy = "t", Status = CertificateRequestStatus.Issued, CertificatePem = "pem" },
            new CertificateRequest { CommonName = "pending", RequestedBy = "t" });
        await db.SaveChangesAsync(ct);

        var issuer = await IssuerBootstrap.EnsureLegacyIssuerAsync(db, Legacy(), null, TimeProvider.System, ct);

        await using var check = database.CreateContext();
        Assert.Equal(issuer!.Id, (await check.CertificateRequests.SingleAsync(r => r.CommonName == "issued", ct)).IssuerId);
        Assert.Null((await check.CertificateRequests.SingleAsync(r => r.CommonName == "pending", ct)).IssuerId);
    }

    [Fact]
    public async Task Bootstrap_IsIdempotent()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        var legacy = Legacy();
        await using (var db = database.CreateContext())
            await IssuerBootstrap.EnsureLegacyIssuerAsync(db, legacy, null, TimeProvider.System, ct);
        await using (var db = database.CreateContext())
            await IssuerBootstrap.EnsureLegacyIssuerAsync(db, legacy, null, TimeProvider.System, ct);

        await using var check = database.CreateContext();
        Assert.Equal(1, await check.Issuers.CountAsync(ct));
    }

    [Fact]
    public async Task Bootstrap_ConcurrentCallers_InsertOneRow()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        var legacy = Legacy();

        var tasks = Enumerable.Range(0, 4).Select(async _ =>
        {
            await using var db = database.CreateContext();
            return await IssuerBootstrap.EnsureLegacyIssuerAsync(db, legacy, null, TimeProvider.System, ct);
        });
        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.NotNull(r));
        await using var check = database.CreateContext();
        Assert.Equal(1, await check.Issuers.CountAsync(ct));
    }

    [Fact]
    public async Task Bootstrap_KeepsCrlNumberSequence()
    {
        // The legacy issuer keeps claiming from CaSettings (plan refinement 3): bootstrap must not
        // touch the counter, so the first CRL after upgrade is N + 1.
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        await using var db = database.CreateContext();
        db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, Id = 1, CrlNumber = 41 });
        await db.SaveChangesAsync(ct);

        await IssuerBootstrap.EnsureLegacyIssuerAsync(db, Legacy(), null, TimeProvider.System, ct);

        await using var check = database.CreateContext();
        Assert.Equal(41, (await check.Settings.SingleAsync(ct)).CrlNumber);
    }

    [Fact]
    public async Task Bootstrap_WhenOtherIssuersExist_DoesNotReRegisterLegacyFiles()
    {
        // After a force replace destroyed the legacy issuer, leftover files must not resurrect it.
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        db.Issuers.Add(IssuerModelTests.Row("other", isDefault: true));
        await db.SaveChangesAsync(ct);

        var result = await IssuerBootstrap.EnsureLegacyIssuerAsync(db, Legacy(), null, TimeProvider.System, ct);

        Assert.NotNull(result);          // returns the default it found
        Assert.Equal("other", result.Name);
        Assert.Equal(1, await db.Issuers.CountAsync(ct));
    }
}
