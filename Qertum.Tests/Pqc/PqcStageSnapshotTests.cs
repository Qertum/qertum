using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;

namespace Qertum.Tests.Pqc;

public sealed class PqcStageSnapshotTests
{
    private static readonly DateTime Now = new(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);
    private static readonly List<SharedInMemoryDatabase> Anchors = [];

    private static PqcContext Rsa(string type = "WebServer", string[]? names = null, bool renewal = false) =>
        new(type, CertificateKeyAlgorithm.Rsa, names ?? ["app.corp.example"], false, renewal);

    private static async Task<(CertificateRequestDbContext Db, PqcStageService Service)> ArrangeAsync(
        PqcStage? defaultStage = PqcStage.Off)
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        lock (Anchors) Anchors.Add(database);   // nothing else references the anchor connection
        var db = database.CreateContext();
        if (defaultStage is { } stage)
        {
            db.Settings.Add(new CaSettings { Id = 1, PqcStage = stage });
            await db.SaveChangesAsync();
        }
        return (db, new PqcStageService(db, null, new FakeTimeProvider(new DateTimeOffset(Now))));
    }

    [Fact]
    public async Task StageOverride_ReplacesBothTheTemplateOverrideAndTheDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Off);
        await using var _ = db;
        (await db.CertificateTemplates.FirstAsync(t => t.TypeKey == "WebServer", ct)).PqcStageOverride = PqcStage.Enforce;
        await db.SaveChangesAsync(ct);

        var snapshot = await service.LoadSnapshotAsync(PqcStage.Warn, ct);

        Assert.Equal(PqcStage.Warn, snapshot.Evaluate(Rsa("WebServer")).Verdict.Stage);
        Assert.Equal(PqcStage.Warn, snapshot.Evaluate(Rsa("ClientAuth")).Verdict.Stage);
        Assert.Equal(PqcStage.Enforce, snapshot.CurrentStageFor("WebServer", isCaKey: false));
        Assert.Equal(PqcStage.Off, snapshot.CurrentStageFor("ClientAuth", isCaKey: false));
        Assert.Equal(PqcStage.Warn, snapshot.EffectiveStageFor("ClientAuth", isCaKey: false));
    }

    [Fact]
    public async Task WithoutAnOverride_TheSnapshotDecidesLikeEvaluateAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Pilot);
        await using var _ = db;

        var snapshot = await service.LoadSnapshotAsync(cancellationToken: ct);

        foreach (var renewal in new[] { false, true })
            Assert.Equal(await service.EvaluateAsync(Rsa(renewal: renewal), ct), snapshot.Evaluate(Rsa(renewal: renewal)).Verdict);
    }

    [Fact]
    public async Task EvaluateAsync_WithAnOverride_MatchesTheSnapshot()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Off);
        await using var _ = db;

        var verdict = await service.EvaluateAsync(Rsa(), PqcStage.Enforce, ct);

        Assert.Equal(PqcOutcome.Refused, verdict.Outcome);
        Assert.Equal(PqcStage.Enforce, verdict.Stage);
    }

    [Fact]
    public async Task TheSnapshot_NamesTheExceptionThatCoveredARefusal()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Off);
        await using var _ = db;
        var exception = new PqcException
        {
            TemplateTypeKey = "WebServer", NamePattern = "corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(1), Reason = "legacy", GrantedBy = "admin", CreatedAtUtc = Now
        };
        db.PqcExceptions.Add(exception);
        await db.SaveChangesAsync(ct);

        var evaluation = (await service.LoadSnapshotAsync(PqcStage.Enforce, ct)).Evaluate(Rsa());

        Assert.Equal(PqcOutcome.AllowedWithWarning, evaluation.Verdict.Outcome);
        Assert.Equal(exception.Id, evaluation.ExceptionId);
    }

    [Fact]
    public async Task AnUnrelatedRequest_HasNoExceptionId()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Enforce);
        await using var _ = db;

        Assert.Null((await service.LoadSnapshotAsync(cancellationToken: ct)).Evaluate(Rsa()).ExceptionId);
    }

    [Fact]
    public async Task ExpiredAndRevokedExceptions_NeverCover()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(PqcStage.Enforce);
        await using var _ = db;
        db.PqcExceptions.AddRange(
            new PqcException { TemplateTypeKey = "WebServer", NamePattern = "corp.example", Family = PqcExceptionFamily.Rsa,
                ExpiresAtUtc = Now, Reason = "x", GrantedBy = "a", CreatedAtUtc = Now.AddDays(-9) },
            new PqcException { TemplateTypeKey = "WebServer", NamePattern = "corp.example", Family = PqcExceptionFamily.Rsa,
                ExpiresAtUtc = Now.AddDays(9), Reason = "x", GrantedBy = "a", CreatedAtUtc = Now.AddDays(-9),
                RevokedBy = "a", RevokedAtUtc = Now.AddDays(-1) });
        await db.SaveChangesAsync(ct);

        Assert.Equal(PqcOutcome.Refused, (await service.LoadSnapshotAsync(cancellationToken: ct)).Evaluate(Rsa()).Verdict.Outcome);
    }

    [Fact]
    public async Task NoSettingsRow_IsEnforce_AndLoadingASnapshotInsertsNone()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service) = await ArrangeAsync(defaultStage: null);
        await using var _ = db;

        var snapshot = await service.LoadSnapshotAsync(cancellationToken: ct);

        Assert.Equal(PqcStage.Enforce, snapshot.DefaultStage);
        Assert.Equal(PqcStage.Enforce, snapshot.CurrentStageFor("WebServer", isCaKey: false));
        Assert.False(await db.Settings.AnyAsync(ct));
    }
}
