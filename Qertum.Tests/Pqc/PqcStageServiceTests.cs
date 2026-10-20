using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Pqc;

public sealed class PqcStageServiceTests
{
    private static readonly List<SharedInMemoryDatabase> Anchors = [];
    private static readonly DateTime Now = new(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc);

    private sealed class Recorder : IDiagnosticEventLog
    {
        public List<(string Subject, Guid Id, string Action, string By, string? Category)> Events { get; } = [];
        public void Record(string subjectType, Guid subjectId, string action, string performedBy,
            string? category = null, string? detail = null, object? data = null) =>
            Events.Add((subjectType, subjectId, action, performedBy, category));
    }

    private static PqcContext Rsa(string type = "WebServer", string[]? names = null, bool renewal = false, bool ca = false) =>
        new(type, CertificateKeyAlgorithm.Rsa, names ?? ["app.corp.example"], false, renewal, ca);

    private static async Task<(CertificateRequestDbContext Db, PqcStageService Service, Recorder Log, SharedInMemoryDatabase Database)> ArrangeAsync(
        Action<CaSettings>? settings = null, bool seedSettings = true)
    {
        var database = SharedInMemoryDatabase.Create(createSchema: true, seedSettings: false);
        var db = database.CreateContext();
        if (seedSettings)
        {
            var row = new CaSettings { Id = 1 };
            settings?.Invoke(row);
            db.Settings.Add(row);
            await db.SaveChangesAsync();
        }
        var log = new Recorder();
        // Nothing else references the database; its anchor connection must outlive the test.
        lock (Anchors) Anchors.Add(database);
        return (db, new PqcStageService(db, log, new FakeTimeProvider(new DateTimeOffset(Now))), log, database);
    }

    [Fact]
    public async Task NoSettingsRow_IsTreatedAsEnforce_AndNoRowIsInserted()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync(seedSettings: false);
        await using var _1 = db;

        var verdict = await service.EvaluateAsync(Rsa(), ct);

        Assert.Equal(PqcOutcome.Refused, verdict.Outcome);
        Assert.Equal(PqcStage.Enforce, verdict.Stage);
        Assert.False(await db.Settings.AnyAsync(ct));
    }

    [Fact]
    public async Task TemplateOverride_BeatsTheCaDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync(s => s.PqcStage = PqcStage.Enforce);
        await using var _1 = db;
        (await db.CertificateTemplates.FirstAsync(t => t.TypeKey == "WebServer", ct)).PqcStageOverride = PqcStage.Warn;
        await db.SaveChangesAsync(ct);

        Assert.Equal(PqcOutcome.AllowedWithWarning, (await service.EvaluateAsync(Rsa(), ct)).Outcome);
        Assert.Equal(PqcOutcome.Refused, (await service.EvaluateAsync(Rsa("ClientAuth"), ct)).Outcome);
    }

    [Fact]
    public async Task RequestWithoutATemplate_UsesTheCaDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync(s => s.PqcStage = PqcStage.Warn);
        await using var _1 = db;

        Assert.Equal(PqcStage.Warn, (await service.EvaluateAsync(Rsa("RootCA", ca: true), ct)).Stage);
    }

    [Fact]
    public async Task ActiveException_AdmitsTheRequest_WithAWarningNamingIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync();
        await using var _1 = db;
        var exception = new PqcException
        {
            TemplateTypeKey = "WebServer", NamePattern = "corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(1), Reason = "legacy", GrantedBy = "admin", CreatedAtUtc = Now
        };
        db.PqcExceptions.Add(exception);
        await db.SaveChangesAsync(ct);

        var verdict = await service.EvaluateAsync(Rsa(), ct);

        Assert.Equal(PqcOutcome.AllowedWithWarning, verdict.Outcome);
        Assert.Equal(PqcEventActions.ExceptionApplied, verdict.EventAction);
        Assert.Contains(exception.Id.ToString(), verdict.Reason);
    }

    [Fact]
    public async Task ExtraSanOutsideThePattern_IsStillRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync();
        await using var _1 = db;
        db.PqcExceptions.Add(new PqcException
        {
            TemplateTypeKey = "WebServer", NamePattern = "app.corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(1), Reason = "legacy", GrantedBy = "admin", CreatedAtUtc = Now
        });
        await db.SaveChangesAsync(ct);

        var verdict = await service.EvaluateAsync(Rsa(names: ["app.corp.example", "other.example"]), ct);

        Assert.Equal(PqcOutcome.Refused, verdict.Outcome);
    }

    [Fact]
    public async Task ExceptionNeverAppliesToACaKey()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, _, _) = await ArrangeAsync();
        await using var _1 = db;
        db.PqcExceptions.Add(new PqcException
        {
            TemplateTypeKey = "RootCA", NamePattern = "corp.example", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = Now.AddDays(1), Reason = "x", GrantedBy = "admin", CreatedAtUtc = Now
        });
        await db.SaveChangesAsync(ct);

        Assert.Equal(PqcOutcome.Refused,
            (await service.EvaluateAsync(Rsa("RootCA", names: ["corp.example"], ca: true), ct)).Outcome);
    }

    [Fact]
    public async Task Record_WritesADiagnosticEvent_OnlyWhenTheVerdictHasOne_AndNeverThrows()
    {
        var ct = TestContext.Current.CancellationToken;
        var (db, service, log, _) = await ArrangeAsync(s => s.PqcStage = PqcStage.Warn);
        await using var _1 = db;
        var requestId = Guid.NewGuid();

        service.Record(await service.EvaluateAsync(Rsa(), ct), requestId, "alice");
        service.Record(new PqcVerdict(PqcOutcome.Allowed, PqcStage.Off, null, null), requestId, "alice");

        var recorded = Assert.Single(log.Events);
        Assert.Equal((LifecycleSubjectTypes.CertificateRequest, requestId, PqcEventActions.Warned, "alice", DiagnosticCategories.PqcStage),
            recorded);

        var throwing = new PqcStageService(db, new ThrowingLog());
        throwing.Record(new PqcVerdict(PqcOutcome.AllowedWithWarning, PqcStage.Warn, "r", PqcEventActions.Warned), requestId, "a");
    }

    private sealed class ThrowingLog : IDiagnosticEventLog
    {
        public void Record(string subjectType, Guid subjectId, string action, string performedBy,
            string? category = null, string? detail = null, object? data = null) => throw new InvalidOperationException();
    }
}
